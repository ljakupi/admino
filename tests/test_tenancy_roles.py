"""Role cases of the tenant isolation suite (GH-163, AC "Role cases").

Every capability of #139 §2.1 that has a route is checked at the HTTP layer
against each role: every non-public row of ``ROUTES`` (tests/tenancy_world.py)
is sent by the Super Admin and by org A's Org Admin, Editor and Viewer.

Inputs: the world of ``build_world`` (two orgs, one account per member role,
a Super Admin; real session cookies resolved by the real
``server.require_session``) over the in-memory database of tests/db_fakes.py,
and one prepared request per route (``_SETUPS``, keyed by (method, path)):
whatever the request needs exists in the caller's org (a pending invitation,
a second member, a fresh active or deactivated member to manage (GH-164), a
second session, a pending confirmation or promotion, an OAuth connection, a
target org for the platform routes, a fresh active or deactivated user of org
B for the Super Admin's user actions and an org whose first Org Admin is still
invited for the re-invite (GH-167)). GH-176: the chat routes act on a persisted
chat of the caller's own (a Viewer's too: chats from before a demotion stay
stored, so its 403 is the role's, not a missing chat's) with a live pending
confirmation in ``server._chat_runtime``; the Super Admin, who can own no chat,
is pointed at org A's Org Admin's. The legacy confirm acts on the caller's
legacy chat (``chats.legacy_session_id``) and its pending confirmation. GH-8:
the stop route acts on the caller's own idle chat (no run to stop: ``200
{"stopped": false}``) and never touches the chat runtime. GH-187: the upload
sends a short text file (raw body, ``X-Attachment-Name``) into a chat of the
caller's own (a Viewer's too); the attachment reads name an attachment of a
chat of the caller's own, its file under a per-test attachments root; orgs A
and B have a storage quota. The Super Admin's requests name org A's Org
Admin's chat and attachment. GH-190: the exclusion (``PATCH
/api/attachments/{attachment_id}`` with ``{"active": false}``) and the list of
a chat's files (``GET /api/chats/{chat_id}/attachments``) act on an attachment
and a chat of the caller's own (a Viewer's too).

Outputs (the expectations):
- a role outside ``allowed_roles(spec)`` (the spelled-out ``ROLE_MATRIX``)
  gets exactly ``403 {"detail": "Forbidden"}`` and nothing happens: no table
  changes (chats, chat messages and attachments included), no write
  statement (a session's ``last_seen_at`` refresh aside), no audit row, no
  file under the attachments root (GH-187), no change in the chat runtime
  (entries, pending confirmations), OAuth states or promotions, and the agent
  never runs;
- a role inside it gets the route's documented success status
  (``_SETUPS[...].status``) for the same request.
- GH-187: the three attachment rows are gated by their own capability, not
  just by its roles (``file.upload`` and ``chat.send`` have the same roles):
  with ``access.can`` refusing only the row's capability, the Editor's valid
  request is a 403 that changes nothing. GH-190's two attachment rows
  (``chat.send``) are checked the same way.

Completeness: a new non-public ``ROUTES`` row fails
``test_tenancy_roles_every_non_public_route_has_a_setup`` until it gets a
setup here; a capability that is neither routed (by a route, or by the
service of routes with role cases in ``SERVICE_CAPABILITIES``) nor pending in
``PENDING_CAPABILITIES`` fails the §2.1 coverage test.

Security notes:
- No real network: the OAuth provider revocation, the database health check,
  the LLM reachability probe and the provider model probes are stubbed; the
  OAuth client credentials and the Fernet key are fake values.
- Passwords, tokens and emails are fixed fake values, never secrets.
"""

from __future__ import annotations

import copy
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

from admino import access, org_permissions, server
from admino.access import Capability
from admino.oauth import encrypt_refresh_token
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    FORBIDDEN,
    NEW_PASSWORD,
    PASSWORD,
    PENDING_CAPABILITIES,
    ROLE_MATRIX,
    ROLES,
    ROUTES,
    SERVICE_CAPABILITIES,
    UPLOAD_BODY,
    Account,
    Role,
    RouteSpec,
    World,
    allowed_roles,
    attachment_files,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    route_id,
    seed_attachment,
    seed_chat,
    seed_pending_confirmation,
    stub_agent,
    upload_headers,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from admino.access import Principal

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B with an Org Admin, an Editor and a Viewer each, plus a Super Admin.

    GH-187: attachments live under ``tmp_path``; both orgs have a storage quota.
    """
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture(autouse=True)
def _no_leftover_server_state() -> Iterator[None]:
    """Leave no chat runtime entry, confirmation, OAuth state or promotion to later
    test files (chats themselves live in each test's own FakeDb)."""
    yield
    runtime = getattr(server, "_chat_runtime", None)
    if runtime is not None:
        runtime.clear()
    server._oauth_pending_states.clear()
    org_permissions.clear_pending()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake OAuth credentials and stubs for every outbound call a route could make."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "fake-google-client-id-gh163")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "fake-google-client-secret-gh163")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "fake-microsoft-client-id-gh163")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "fake-microsoft-client-secret-gh163")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "https://admino.example.ch/api/oauth/callback")
    monkeypatch.setattr("admino.oauth._revoke_google_token", AsyncMock(return_value=None))
    monkeypatch.setattr("admino.oauth._revoke_microsoft_token", AsyncMock(return_value=None))
    monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
    monkeypatch.setattr(server, "_check_llm_reachable", AsyncMock(return_value=True))
    monkeypatch.setattr(server, "_get_vllm_available_models", AsyncMock(return_value=[]))
    monkeypatch.setattr(server, "_get_infomaniak_available_models", AsyncMock(return_value=[]))


# ---------------------------------------------------------------------------
# One prepared request per route
# ---------------------------------------------------------------------------

_CHAT_ID: Final = "roles-163"
_CONFIRMATION_ID: Final = "confirm-163"
_INVITEE_EMAIL: Final = "roles-invitee-163@example.ch"
_TARGET_EMAIL: Final = "roles-target-163@example.ch"
_MANAGED_EMAIL: Final = "roles-managed-164@example.ch"
_NEW_ORG_ADMIN_EMAIL: Final = "roles-new-admin-163@example.ch"
_REFRESH_TOKEN: Final = "fake-refresh-token-gh163"
_PLATFORM_TARGET_EMAIL: Final = "roles-platform-target-167@example.ch"
_FIRST_ADMIN_EMAIL: Final = "roles-first-admin-167@example.ch"


@dataclass(frozen=True)
class _Request:
    """One valid request: method, concrete URL, query and JSON body, and (GH-187's upload)
    a raw body with its request headers."""

    method: str
    url: str
    params: dict[str, str] = field(default_factory=dict)
    json: dict[str, Any] | None = None
    content: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _Setup:
    """How to prepare a route's valid request for a caller, and its success status.

    ``prepare`` runs after ``create_app`` (which clears the server's in-memory
    state), so whatever it seeds there survives until the request.
    """

    prepare: Callable[[World, Account], _Request]
    status: int


def _plain(method: str, url: str, **kwargs: Any) -> Callable[[World, Account], _Request]:
    """A request that needs no setup."""

    def prepare(_world: World, _caller: Account) -> _Request:
        return _Request(method, url, **kwargs)

    return prepare


def _caller_org(world: World, caller: Account) -> Any:
    """The caller's org; org A for the Super Admin (who belongs to none)."""
    return caller.org_id if caller.org_id is not None else world.org_a


def _delete_own_session(world: World, caller: Account) -> _Request:
    """The caller's own second session (another device)."""
    second = world.db.open_session(caller.user_id)
    return _Request("DELETE", f"/api/me/sessions/{world.db.session_id_of(second)}")


def _force_logout(world: World, caller: Account) -> _Request:
    """A second member of the caller's org, with a live session."""
    target = world.db.add_account(
        role="editor", org_id=_caller_org(world, caller), email=_TARGET_EMAIL
    )
    world.db.open_session(target)
    return _Request("POST", f"/api/org/users/{target}/logout")


def _disposable_member(world: World, caller: Account, *, status: str = "active") -> Any:
    """A fresh Editor of the caller's org, created per request: never the caller, never
    the org's last Org Admin. An active one has a live session; a deactivated one has
    none (deactivation revoked them). The org keeps free seats (100, 3 members)."""
    target = world.db.add_account(
        role="editor", org_id=_caller_org(world, caller), status=status, email=_MANAGED_EMAIL
    )
    if status == "active":
        world.db.open_session(target)
    return target


def _patch_org_user(world: World, caller: Account) -> _Request:
    """Change a fresh Editor's role to Viewer (a real change: ORG_USERS_ROLE_CHANGE)."""
    return _Request(
        "PATCH", f"/api/org/users/{_disposable_member(world, caller)}", json={"role": "viewer"}
    )


def _deactivate_org_user(world: World, caller: Account) -> _Request:
    """Deactivate a fresh active Editor of the caller's org."""
    return _Request("POST", f"/api/org/users/{_disposable_member(world, caller)}/deactivate")


def _reactivate_org_user(world: World, caller: Account) -> _Request:
    """Reactivate a fresh deactivated Editor of the caller's org (a seat is free)."""
    target = _disposable_member(world, caller, status="deactivated")
    return _Request("POST", f"/api/org/users/{target}/reactivate")


def _delete_org_user(world: World, caller: Account) -> _Request:
    """Delete a fresh active Editor of the caller's org."""
    return _Request("DELETE", f"/api/org/users/{_disposable_member(world, caller)}")


def _org_user_password_reset(world: World, caller: Account) -> _Request:
    """Send a password reset to a fresh active Editor of the caller's org."""
    return _Request("POST", f"/api/org/users/{_disposable_member(world, caller)}/password-reset")


def _pending_invitation(world: World, caller: Account) -> Any:
    """A pending invitation into the caller's org; its id."""
    invitee = world.db.add_account(
        role="viewer",
        org_id=_caller_org(world, caller),
        status="invited",
        name=None,
        password_hash=None,
        email=_INVITEE_EMAIL,
    )
    world.db.add_invitation(invitee)
    invitation = world.db.invitation_of(invitee)
    assert invitation is not None
    return invitation["id"]


def _revoke_invitation(world: World, caller: Account) -> _Request:
    """Revoke a pending invitation of the caller's org."""
    return _Request("DELETE", f"/api/org/invitations/{_pending_invitation(world, caller)}")


def _resend_invitation(world: World, caller: Account) -> _Request:
    """Resend a pending invitation of the caller's org."""
    return _Request("POST", f"/api/org/invitations/{_pending_invitation(world, caller)}/resend")


def _cancel_pending_promotion(world: World, caller: Account) -> _Request:
    """A pending gmail.send promotion in the caller's org (started just now)."""
    org_permissions._pending[(_caller_org(world, caller), "gmail", "send")] = datetime.now(UTC)
    return _Request("DELETE", "/api/org/critical-permissions/gmail/send/pending")


def _chat_owner(world: World, caller: Account) -> Account:
    """The caller, or org A's Org Admin for the Super Admin (who can own no chat)."""
    return caller if caller.org_id is not None else world.a["org_admin"]


def _confirm(world: World, caller: Account) -> _Request:
    """A pending confirmation in the caller's own legacy chat (GH-176: a persisted chat
    with that legacy session id, the pending in the chat runtime); the request denies it."""
    owner = _chat_owner(world, caller)
    chat_id = seed_chat(world.db, owner, legacy_session_id=_CHAT_ID)
    seed_pending_confirmation(owner, chat_id, _CONFIRMATION_ID)
    return _Request(
        "POST",
        f"/api/confirm/{_CONFIRMATION_ID}",
        json={"session_id": _CHAT_ID, "confirmation_id": _CONFIRMATION_ID, "approved": False},
    )


def _own_chat(
    method: str, suffix: str = "", *, json: dict[str, Any] | None = None, history: bool = True
) -> Callable[[World, Account], _Request]:
    """A request on a chat of the caller's own (GH-176), with a live pending confirmation.

    The chat has a title and, with ``history``, a question and its answer. A Viewer
    owns one too (from before a demotion); the Super Admin's request names org A's
    Org Admin's chat.
    """

    def prepare(world: World, caller: Account) -> _Request:
        owner = _chat_owner(world, caller)
        chat_id = seed_chat(
            world.db,
            owner,
            title="Rollen Chat 176",
            messages=(("user", "Rollen Frage 176"), ("assistant", "Rollen Antwort 176"))
            if history
            else (),
        )
        seed_pending_confirmation(owner, chat_id, _CONFIRMATION_ID)
        return _Request(method, f"/api/chats/{chat_id}{suffix}", json=json)

    return prepare


def _upload_attachment(world: World, caller: Account) -> _Request:
    """GH-187: a short text file into a chat of the caller's own (a Viewer owns one from
    before a demotion; the Super Admin's request names org A's Org Admin's chat)."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Rollen Chat 187")
    return _Request(
        "POST",
        f"/api/chats/{chat_id}/attachments",
        content=UPLOAD_BODY,
        headers=upload_headers(),
    )


def _own_attachment(suffix: str) -> Callable[[World, Account], _Request]:
    """GH-187: the metadata (``suffix`` "") or the download ("/content") of an attachment
    of a chat of the caller's own, its file under the attachments root."""

    def prepare(world: World, caller: Account) -> _Request:
        chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Rollen Chat 187")
        attachment_id = seed_attachment(world.db, chat_id, filename="rollen-187.txt")
        return _Request("GET", f"/api/attachments/{attachment_id}{suffix}")

    return prepare


def _exclude_own_attachment(world: World, caller: Account) -> _Request:
    """GH-190: exclude (``{"active": false}``) an attachment of a chat of the caller's own."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Rollen Chat 190")
    attachment_id = seed_attachment(world.db, chat_id, filename="rollen-190.txt")
    return _Request("PATCH", f"/api/attachments/{attachment_id}", json={"active": False})


def _list_own_chat_attachments(world: World, caller: Account) -> _Request:
    """GH-190: the files of a chat of the caller's own (it holds one)."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Rollen Chat 190")
    seed_attachment(world.db, chat_id, filename="rollen-190.txt")
    return _Request("GET", f"/api/chats/{chat_id}/attachments")


def _oauth_disconnect(provider: str) -> Callable[[World, Account], _Request]:
    """Disconnect the caller's own connection (seeded for a member; the Super Admin has none)."""

    def prepare(world: World, caller: Account) -> _Request:
        if caller.org_id is not None:
            world.db.add_oauth_token(
                caller.user_id,
                provider,
                encrypted_refresh_token=encrypt_refresh_token(_REFRESH_TOKEN),
            )
        return _Request("DELETE", f"/api/oauth/{provider}")

    return prepare


def _org_b(method: str, suffix: str, **kwargs: Any) -> Callable[[World, Account], _Request]:
    """A platform request on org B (active)."""

    def prepare(world: World, _caller: Account) -> _Request:
        return _Request(method, f"/api/platform/orgs/{world.org_b}/{suffix}", **kwargs)

    return prepare


def _org_b_in(status: str, method: str, suffix: str) -> Callable[[World, Account], _Request]:
    """A platform request on org B, first put in ``status``."""

    def prepare(world: World, _caller: Account) -> _Request:
        world.db.add_org(world.org_b, status=status)
        return _Request(method, f"/api/platform/orgs/{world.org_b}/{suffix}")

    return prepare


def _org_b_user(action: str, *, status: str = "active") -> Callable[[World, Account], _Request]:
    """A Super Admin user action (GH-167) on a fresh Editor of org B in ``status``.

    An active one has a live session (a refused deactivation must leave it); a
    deactivated one has none. Org B keeps free seats and its own Org Admin.
    """

    def prepare(world: World, _caller: Account) -> _Request:
        target = world.db.add_account(
            role="editor", org_id=world.org_b, status=status, email=_PLATFORM_TARGET_EMAIL
        )
        if status == "active":
            world.db.open_session(target)
        return _Request("POST", f"/api/platform/orgs/{world.org_b}/users/{target}/{action}")

    return prepare


def _reinvite_first_org_admin(world: World, _caller: Account) -> _Request:
    """A fresh active org whose first Org Admin is still invited (so it has no active
    Org Admin): resend that invitation, with no request body (GH-167)."""
    org_id = world.db.add_org(name="Rollen Einladung AG")
    invited = world.db.add_account(
        role="org_admin",
        org_id=org_id,
        status="invited",
        name=None,
        password_hash=None,
        email=_FIRST_ADMIN_EMAIL,
    )
    world.db.add_invitation(invited)
    return _Request("POST", f"/api/platform/orgs/{org_id}/users/{invited}/invitation")


_SETUPS: Final[dict[tuple[str, str], _Setup]] = {
    # --- own account ---
    ("POST", "/api/auth/logout"): _Setup(_plain("POST", "/api/auth/logout"), 204),
    ("GET", "/api/auth/me"): _Setup(_plain("GET", "/api/auth/me"), 200),
    ("GET", "/api/me/sessions"): _Setup(_plain("GET", "/api/me/sessions"), 200),
    ("DELETE", "/api/me/sessions/{session_id}"): _Setup(_delete_own_session, 204),
    ("GET", "/api/me/settings"): _Setup(_plain("GET", "/api/me/settings"), 200),
    ("PATCH", "/api/me/settings"): _Setup(
        _plain("PATCH", "/api/me/settings", json={"appearance": {"theme": "dark"}}), 200
    ),
    ("POST", "/api/me/settings/reset"): _Setup(_plain("POST", "/api/me/settings/reset"), 200),
    ("GET", "/api/me"): _Setup(_plain("GET", "/api/me"), 200),
    ("PATCH", "/api/me"): _Setup(_plain("PATCH", "/api/me", json={"timezone": "Asia/Tokyo"}), 200),
    # A real change (204); each case builds its own world, so ending the caller's
    # sessions affects no other case.
    ("POST", "/api/me/password"): _Setup(
        _plain(
            "POST",
            "/api/me/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        ),
        204,
    ),
    # --- org users and invitations ---
    ("GET", "/api/org/users"): _Setup(_plain("GET", "/api/org/users"), 200),
    ("PATCH", "/api/org/users/{user_id}"): _Setup(_patch_org_user, 200),
    ("POST", "/api/org/users/{user_id}/deactivate"): _Setup(_deactivate_org_user, 200),
    ("POST", "/api/org/users/{user_id}/reactivate"): _Setup(_reactivate_org_user, 200),
    ("DELETE", "/api/org/users/{user_id}"): _Setup(_delete_org_user, 204),
    ("POST", "/api/org/users/{user_id}/password-reset"): _Setup(_org_user_password_reset, 202),
    ("POST", "/api/org/users/{user_id}/logout"): _Setup(_force_logout, 204),
    ("POST", "/api/org/invitations"): _Setup(
        _plain("POST", "/api/org/invitations", json={"email": _INVITEE_EMAIL, "role": "editor"}),
        201,
    ),
    ("GET", "/api/org/invitations"): _Setup(_plain("GET", "/api/org/invitations"), 200),
    ("DELETE", "/api/org/invitations/{invitation_id}"): _Setup(_revoke_invitation, 204),
    ("POST", "/api/org/invitations/{invitation_id}/resend"): _Setup(_resend_invitation, 200),
    # --- org settings and tool permissions ---
    ("GET", "/api/org/settings"): _Setup(_plain("GET", "/api/org/settings"), 200),
    ("PATCH", "/api/org/settings"): _Setup(
        _plain("PATCH", "/api/org/settings", json={"tools": {"gmail": False}}), 200
    ),
    ("GET", "/api/org/permissions"): _Setup(_plain("GET", "/api/org/permissions"), 200),
    ("PATCH", "/api/org/permissions"): _Setup(
        _plain(
            "PATCH",
            "/api/org/permissions",
            json={"tool": "gmail", "action": "read", "permission": "confirm"},
        ),
        200,
    ),
    ("GET", "/api/org/critical-permissions"): _Setup(
        _plain("GET", "/api/org/critical-permissions"), 200
    ),
    ("PATCH", "/api/org/critical-permissions/{tool}/{action}"): _Setup(
        _plain("PATCH", "/api/org/critical-permissions/gmail/send", json={"password": PASSWORD}),
        200,
    ),
    ("DELETE", "/api/org/critical-permissions/{tool}/{action}/pending"): _Setup(
        _cancel_pending_promotion, 200
    ),
    ("GET", "/api/permissions/summary"): _Setup(_plain("GET", "/api/permissions/summary"), 200),
    # --- chat ---
    ("POST", "/api/message"): _Setup(
        _plain(
            "POST",
            "/api/message",
            json={"message": "Hello from the role suite.", "session_id": _CHAT_ID},
        ),
        200,
    ),
    ("POST", "/api/confirm/{confirmation_id}"): _Setup(_confirm, 200),
    # GH-176: persisted chats (a title on create: "user"; the turn runs the stub agent).
    ("POST", "/api/chats"): _Setup(
        _plain("POST", "/api/chats", json={"title": "Neuer Rollen Chat 176"}), 201
    ),
    ("GET", "/api/chats"): _Setup(_plain("GET", "/api/chats"), 200),
    ("GET", "/api/chats/{chat_id}"): _Setup(_own_chat("GET"), 200),
    ("PATCH", "/api/chats/{chat_id}"): _Setup(
        _own_chat("PATCH", json={"title": "Umbenannter Rollen Chat 176"}), 200
    ),
    ("DELETE", "/api/chats/{chat_id}"): _Setup(_own_chat("DELETE"), 204),
    ("POST", "/api/chats/{chat_id}/messages"): _Setup(
        _own_chat(
            "POST", "/messages", json={"message": "Hello from the role suite."}, history=False
        ),
        200,
    ),
    # GH-8: stop the caller's own idle chat (no streamed run: 200 {"stopped": false}).
    ("POST", "/api/chats/{chat_id}/stop"): _Setup(_own_chat("POST", "/stop"), 200),
    # GH-187: upload into the caller's own chat (201, status "uploaded"); its metadata and
    # download (200).
    ("POST", "/api/chats/{chat_id}/attachments"): _Setup(_upload_attachment, 201),
    ("GET", "/api/attachments/{attachment_id}"): _Setup(_own_attachment(""), 200),
    ("GET", "/api/attachments/{attachment_id}/content"): _Setup(_own_attachment("/content"), 200),
    # GH-190: exclude an attachment of the caller's own (200 with its summary); list a
    # chat's attachments (200).
    ("PATCH", "/api/attachments/{attachment_id}"): _Setup(_exclude_own_attachment, 200),
    ("GET", "/api/chats/{chat_id}/attachments"): _Setup(_list_own_chat_attachments, 200),
    # --- own Google/Microsoft connections ---
    ("GET", "/api/oauth/google/authorize"): _Setup(
        _plain("GET", "/api/oauth/google/authorize"), 200
    ),
    ("GET", "/api/oauth/microsoft/authorize"): _Setup(
        _plain("GET", "/api/oauth/microsoft/authorize"), 200
    ),
    ("GET", "/api/oauth/google/status"): _Setup(_plain("GET", "/api/oauth/google/status"), 200),
    ("GET", "/api/oauth/microsoft/status"): _Setup(
        _plain("GET", "/api/oauth/microsoft/status"), 200
    ),
    ("DELETE", "/api/oauth/google"): _Setup(_oauth_disconnect("google"), 200),
    ("DELETE", "/api/oauth/microsoft"): _Setup(_oauth_disconnect("microsoft"), 200),
    # --- platform (Super Admin) ---
    ("GET", "/api/platform/orgs"): _Setup(_plain("GET", "/api/platform/orgs"), 200),
    ("POST", "/api/platform/orgs"): _Setup(
        _plain(
            "POST",
            "/api/platform/orgs",
            json={
                "name": "Rollen Suite AG",
                "primary_admin_email": _NEW_ORG_ADMIN_EMAIL,
                "seats": 12,
                "monthly_budget_chf": "123.45",
                "storage_quota": 5 * 1024**3,
                "status": "active",
            },
        ),
        201,
    ),
    ("PATCH", "/api/platform/orgs/{org_id}/limits"): _Setup(
        _org_b("PATCH", "limits", json={"seats": 12}), 200
    ),
    ("POST", "/api/platform/orgs/{org_id}/deactivate"): _Setup(_org_b("POST", "deactivate"), 200),
    ("POST", "/api/platform/orgs/{org_id}/reactivate"): _Setup(
        _org_b_in("deactivated", "POST", "reactivate"), 200
    ),
    ("POST", "/api/platform/orgs/{org_id}/deletion"): _Setup(_org_b("POST", "deletion"), 200),
    ("DELETE", "/api/platform/orgs/{org_id}/deletion"): _Setup(
        _org_b_in("pending_deletion", "DELETE", "deletion"), 200
    ),
    ("PATCH", "/api/platform/orgs/{org_id}/residency"): _Setup(
        _org_b("PATCH", "residency", json={"enabled": True}), 200
    ),
    # GH-167: org B's accounts and metadata; the user actions on a user of org B.
    ("GET", "/api/platform/orgs/{org_id}/users"): _Setup(_org_b("GET", "users"), 200),
    ("GET", "/api/platform/orgs/{org_id}/metadata"): _Setup(_org_b("GET", "metadata"), 200),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/deactivate"): _Setup(
        _org_b_user("deactivate"), 200
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/reactivate"): _Setup(
        _org_b_user("reactivate", status="deactivated"), 200
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/password-reset"): _Setup(
        _org_b_user("password-reset"), 202
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/invitation"): _Setup(
        _reinvite_first_org_admin, 200
    ),
    ("GET", "/api/platform/diagnostics"): _Setup(_plain("GET", "/api/platform/diagnostics"), 200),
    ("GET", "/api/platform/settings"): _Setup(_plain("GET", "/api/platform/settings"), 200),
    ("PATCH", "/api/platform/settings"): _Setup(
        _plain("PATCH", "/api/platform/settings", json={"limits": {"max_message_length": 4000}}),
        200,
    ),
}

# ---------------------------------------------------------------------------
# The cases: every non-public route x every role
# ---------------------------------------------------------------------------

_NON_PUBLIC: Final[tuple[RouteSpec, ...]] = tuple(
    spec for spec in ROUTES if spec.audience != "public"
)
_ROLE_CASES: Final[tuple[tuple[RouteSpec, Role], ...]] = tuple(
    (spec, role) for spec in _NON_PUBLIC for role in ROLES
)


def _params(*, allowed: bool) -> list[Any]:
    """The (spec, role) cases whose role is (or isn't) allowed, with readable ids."""
    return [
        pytest.param(spec, role, id=f"{route_id(spec)}-{role}")
        for spec, role in _ROLE_CASES
        if (role in allowed_roles(spec)) is allowed
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A write statement: INSERT, UPDATE ... SET or DELETE, wherever it appears (CTEs too).
_WRITE_RE: Final = re.compile(r"\b(?:insert into|update \w+ set|delete from)\b")
# The session refresh of require_session (at most once a minute), not a side effect.
_SESSION_TOUCH_RE: Final = re.compile(r"^update sessions set last_seen_at = now\(\)")


def _tables(db: FakeDb) -> dict[str, Any]:
    """Every table, deep-copied; a session's ``last_seen_at`` (the refresh) left out."""
    state = db.snapshot()
    state["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in state["sessions"].items()
    }
    return state


def _memory_state(db: FakeDb) -> dict[str, Any]:
    """The server's in-memory state: the chat runtime (its entries and the pending
    confirmation of every stored chat), OAuth states and pending promotions."""
    return copy.deepcopy(
        {
            "chat_runtime": chat_runtime_state(db),
            "oauth_states": dict(server._oauth_pending_states),
            "promotions": dict(org_permissions._pending),
        }
    )


def _writes_since(db: FakeDb, start: int) -> list[str]:
    """The write statements issued after call ``start``, the session refresh aside."""
    return [
        call.normalized
        for call in db.calls[start:]
        if _WRITE_RE.search(call.normalized) and not _SESSION_TOUCH_RE.match(call.normalized)
    ]


# ---------------------------------------------------------------------------
# Role cases
# ---------------------------------------------------------------------------


class TestForbiddenRoles:
    """A role the matrix doesn't allow gets 403 Forbidden and nothing happens."""

    @pytest.mark.parametrize(("spec", "role"), _params(allowed=False))
    def test_tenancy_roles_forbidden_role_gets_exactly_403_forbidden(
        self, world: World, spec: RouteSpec, role: Role
    ) -> None:
        """The valid request of a refused role answers 403 ``{"detail": "Forbidden"}``."""
        app = make_app()
        caller = world.by_role(role)
        request = _SETUPS[(spec.method, spec.path)].prepare(world, caller)

        response = make_client(app).request(
            request.method,
            request.url,
            params=request.params,
            json=request.json,
            content=request.content,
            headers={**request.headers, **caller.cookie},
        )

        assert (response.status_code, response.json()) == (403, FORBIDDEN)

    @pytest.mark.parametrize(("spec", "role"), _params(allowed=False))
    def test_tenancy_roles_forbidden_role_changes_nothing(
        self, world: World, spec: RouteSpec, role: Role
    ) -> None:
        """No table, audit row, write statement, file under the attachments root (GH-187)
        or in-memory state changes; no agent run."""
        agent = stub_agent()
        app = make_app(agent)
        caller = world.by_role(role)
        request = _SETUPS[(spec.method, spec.path)].prepare(world, caller)
        tables = _tables(world.db)
        audit = copy.deepcopy(world.db.audit_rows())
        memory = _memory_state(world.db)
        files = attachment_files()
        start = len(world.db.calls)

        response = make_client(app).request(
            request.method,
            request.url,
            params=request.params,
            json=request.json,
            content=request.content,
            headers={**request.headers, **caller.cookie},
        )

        assert response.status_code == 403
        assert world.db.audit_rows() == audit
        assert _writes_since(world.db, start) == []
        assert _tables(world.db) == tables
        assert _memory_state(world.db) == memory
        assert attachment_files() == files
        agent.run.assert_not_awaited()


class TestAllowedRoles:
    """A role the matrix allows gets the route's success status for a valid request."""

    @pytest.mark.parametrize(("spec", "role"), _params(allowed=True))
    def test_tenancy_roles_allowed_role_gets_the_success_status(
        self, world: World, spec: RouteSpec, role: Role
    ) -> None:
        """The documented 200/201/202/204 (never a 403) for the caller's valid request."""
        app = make_app()
        caller = world.by_role(role)
        setup = _SETUPS[(spec.method, spec.path)]
        request = setup.prepare(world, caller)

        response = make_client(app).request(
            request.method,
            request.url,
            params=request.params,
            json=request.json,
            content=request.content,
            headers={**request.headers, **caller.cookie},
        )

        assert response.status_code == setup.status, response.text[:200]


# ---------------------------------------------------------------------------
# GH-187: each attachment route checks its own row's capability
# ---------------------------------------------------------------------------

_ATTACHMENT_ROUTES: Final[tuple[tuple[str, str], ...]] = (
    ("POST", "/api/chats/{chat_id}/attachments"),
    ("GET", "/api/attachments/{attachment_id}"),
    ("GET", "/api/attachments/{attachment_id}/content"),
    # GH-190
    ("PATCH", "/api/attachments/{attachment_id}"),
    ("GET", "/api/chats/{chat_id}/attachments"),
)


def _refuse_only(monkeypatch: pytest.MonkeyPatch, refused: Capability) -> None:
    """Make ``access.can`` refuse ``refused`` to everyone and answer as before otherwise,
    wherever a module of the app holds a reference to it (``server.can`` included)."""
    real_can = access.can

    def spy(principal: Principal, capability: Capability) -> bool:
        return capability != refused and real_can(principal, capability)

    for name, module in list(sys.modules.items()):
        if (name == "admino" or name.startswith("admino.")) and getattr(
            module, "can", None
        ) is real_can:
            monkeypatch.setattr(module, "can", spy)


class TestAttachmentRouteCapabilities:
    """``file.upload`` and ``chat.send`` have the same roles (Org Admin, Editor), so the
    role cases can't tell which one a route checks: refusing only the row's own
    capability does."""

    @pytest.mark.parametrize(
        "route", [pytest.param(route, id=f"{route[0]}:{route[1]}") for route in _ATTACHMENT_ROUTES]
    )
    def test_tenancy_roles_attachment_route_checks_its_rows_own_capability(
        self, world: World, monkeypatch: pytest.MonkeyPatch, route: tuple[str, str]
    ) -> None:
        """With ``can`` refusing only the row's capability (``file.upload`` for the upload,
        ``chat.send`` for the reads and GH-190's exclusion and list), org A's Editor's valid
        request (its JSON body and query included) is 403 Forbidden and
        changes nothing (no table, audit row or file). Control: before the refusal, the
        same request succeeds with the route's documented status."""
        spec = next(spec for spec in ROUTES if (spec.method, spec.path) == route)
        assert spec.capability is not None
        setup = _SETUPS[route]
        caller = world.a["editor"]
        client = make_client(make_app())
        control = setup.prepare(world, caller)
        allowed = client.request(
            control.method,
            control.url,
            params=control.params,
            json=control.json,
            content=control.content,
            headers={**control.headers, **caller.cookie},
        )
        _refuse_only(monkeypatch, spec.capability)
        request = setup.prepare(world, caller)
        tables = _tables(world.db)
        files = attachment_files()

        response = client.request(
            request.method,
            request.url,
            params=request.params,
            json=request.json,
            content=request.content,
            headers={**request.headers, **caller.cookie},
        )

        assert allowed.status_code == setup.status, allowed.text[:200]
        assert (response.status_code, response.json()) == (403, FORBIDDEN)
        assert _tables(world.db) == tables
        assert attachment_files() == files


# ---------------------------------------------------------------------------
# Completeness and §2.1 coverage
# ---------------------------------------------------------------------------


class TestRoleCaseCoverage:
    """New routes and capabilities can't slip past the role cases."""

    def test_tenancy_roles_every_non_public_route_has_a_setup(self) -> None:
        """Each non-public ROUTES row has a prepared request here, and no setup is stale.

        A route added to tests/tenancy_world.py without a ``_SETUPS`` entry in
        tests/test_tenancy_roles.py fails here (and so has no role cases).
        """
        routes = {(spec.method, spec.path) for spec in _NON_PUBLIC}

        assert {
            "missing": sorted(routes - set(_SETUPS)),
            "stale": sorted(set(_SETUPS) - routes),
        } == {"missing": [], "stale": []}

    def test_tenancy_roles_success_statuses_are_documented_ones(self) -> None:
        """Every setup expects a success status: 200, 201, 202 (an admin-triggered
        password reset, GH-164 and GH-167) or 204."""
        assert {
            key: setup.status
            for key, setup in _SETUPS.items()
            if setup.status not in (200, 201, 202, 204)
        } == {}

    def test_tenancy_roles_every_route_is_checked_against_every_role(self) -> None:
        """The cases are the full cross product: each non-public route x each of the 4 roles."""
        by_route: dict[tuple[str, str], set[Role]] = {}
        for spec, role in _ROLE_CASES:
            by_route.setdefault((spec.method, spec.path), set()).add(role)

        assert len(_NON_PUBLIC) > 0
        assert all(roles == set(ROLES) for roles in by_route.values())
        assert set(by_route) == {(spec.method, spec.path) for spec in _NON_PUBLIC}

    def test_tenancy_roles_every_routed_capability_has_role_cases(self) -> None:
        """§2.1: every capability is either exercised by a role case or pending its issue.

        A service capability counts as exercised when every route whose service
        checks it has role cases (tests/test_tenancy.py pins that it shares their roles).
        """
        exercised = {spec.capability for spec, _role in _ROLE_CASES if spec.capability is not None}
        cased_routes = {(spec.method, spec.path) for spec, _role in _ROLE_CASES}
        exercised |= {
            capability
            for capability, routes in SERVICE_CAPABILITIES.items()
            if routes and set(routes) <= cased_routes
        }

        assert {
            "uncovered": sorted(set(Capability) - exercised - set(PENDING_CAPABILITIES)),
            "routed_but_pending": sorted(exercised & set(PENDING_CAPABILITIES)),
        } == {"uncovered": [], "routed_but_pending": []}

    def test_tenancy_roles_chat_state_in_memory_is_only_the_chat_runtime(self) -> None:
        """GH-176: ``server._chat_runtime`` exists (locks and pending confirmations) and the
        removed in-memory chat dicts are gone, so ``_memory_state`` sees every in-memory
        chat change a refused request could make."""
        runtime = getattr(server, "_chat_runtime", None)
        leftovers = [
            name
            for name in ("_sessions", "_pending_confirmations", "_session_locks")
            if hasattr(server, name)
        ]

        assert runtime is not None
        assert all(
            callable(getattr(runtime, name, None))
            for name in ("get_pending", "set_pending", "clear", "__len__")
        )
        assert leftovers == []

    def test_tenancy_roles_matrix_covers_every_capability(self) -> None:
        """The spelled-out §2.1 matrix names every capability, each with at least one role."""
        assert set(ROLE_MATRIX) == set(Capability)
        assert all(ROLE_MATRIX[capability] for capability in Capability)

    def test_tenancy_roles_cases_include_allowed_and_forbidden_ones(self) -> None:
        """The suite isn't vacuous: every role is refused somewhere, and allowed somewhere."""
        forbidden = {role for spec, role in _ROLE_CASES if role not in allowed_roles(spec)}
        allowed = {role for spec, role in _ROLE_CASES if role in allowed_roles(spec)}

        assert forbidden == set(ROLES)
        assert allowed == set(ROLES)
