"""Tenant isolation and authorization suite (GH-163): the entry point.

The suite proves, at the HTTP layer, that one organization never reaches
another's data, that every route authorizes its caller, and that the Super
Admin (the operator) sees no content. It runs in ``make check`` with the rest
of tests/ and is made of five files:

- ``tests/tenancy_world.py``: the shared world (orgs A and B, each with an Org
  Admin, an Editor and a Viewer, plus a Super Admin, all with live sessions in
  the FakeDb of tests/db_fakes.py) and the route catalog: ``ROUTES`` (every
  registered API route with its audience, gating capability and isolation
  kind), ``ROLE_MATRIX`` (#139 §2.1 spelled out from the tracker),
  ``PENDING_CAPABILITIES``, ``SERVICE_CAPABILITIES`` and ``PROJECT_ROLES``
  (#139 §2.2).
- ``tests/test_tenancy.py`` (this file): the world fixture and its sanity
  check; route enumeration (every registered route has a catalog row and the
  catalog has no stale row, every non-public route depends on
  ``server.require_session``, every capability is routed (by a route or by
  a route's service) or pending, the catalog agrees with ``access.can``);
  operator blindness (the Super Admin gets 403/404 with a bare
  ``{"detail": ...}`` on every member route, and platform response models
  carry no title/name/content/file name field except the org name); request
  bodies (every non-public body model forbids extra fields, so
  a smuggled ``org_id``/``user_id`` is a 422 that changes nothing and echoes
  nothing; this absorbs #17's "request bodies" line); and rate limiting (every
  non-public route spends a per-user bucket, every public route a per-IP one,
  never a bucket shared by all callers).
- ``tests/test_tenancy_roles.py``: every non-public route against every role
  (#139 §2.1 at the HTTP layer).
- ``tests/test_tenancy_cross_org.py``: org A's callers against org B's ids and
  data (404, never 403; same body as an unknown id; nothing changes).
- ``tests/test_tenancy_memory.py``: the memory row, through the chat (memory
  has no HTTP route), including LLM-supplied foreign ids in tool arguments.

GH-176 adds the six persisted chat routes (requests on a chat of the
caller's own, seeded in the FakeDb; the Super Admin's name org A's Editor's)
and backs the legacy confirm with a persisted legacy chat and a pending
confirmation in ``server._chat_runtime``. GH-8 removes ``GET /api/events`` and
adds ``POST /api/chats/{chat_id}/stop`` (no body; a request on the caller's own
idle chat). GH-187 adds the upload ``POST /api/chats/{chat_id}/attachments`` (a
raw body: a short text file, its name in ``X-Attachment-Name``, into a chat of
the caller's own) and the attachment reads ``GET /api/attachments/{attachment_id}``
and ``.../content`` (an attachment of the caller's own chat, its file on disk
under a per-test attachments root); orgs A and B get a storage quota. Its
section 6 pins the upload's cross-site refusal (403, nothing stored). GH-190
adds ``PATCH /api/attachments/{attachment_id}`` (``{"active": false}`` on an
attachment of the caller's own chat: a JSON body) and ``GET
/api/chats/{chat_id}/attachments`` (the files of a chat of the caller's own).
GH-245 adds ``POST /api/chats/{chat_id}/retry`` (no body; a request on a chat of the
caller's own whose one turn failed, so the stub agent re-runs it: 200). Its section 7
pins the retry's cross-site refusal (403, nothing run or changed).

Adding a route (each later issue): give it a ``RouteSpec`` row in
``ROUTES`` (tests/tenancy_world.py), a well-formed request in ``_REQUESTS``
below (and in ``_BODY_ROUTES`` when it takes a JSON body), its role cases in
tests/test_tenancy_roles.py and its cross-org case in
tests/test_tenancy_cross_org.py. The completeness tests of each file fail until
all of these exist. A capability moves from ``PENDING_CAPABILITIES`` to the row
of its first route, or to ``SERVICE_CAPABILITIES`` when it gates part of an
existing route's service (it must then share that route's roles).

Inputs: the FakeDb world, the app from ``create_app()`` with a stub agent, real
session cookies. Outputs: assertions only.

Security notes: every id, email and password here is a fixed fake value. No
test reaches Google, Microsoft or an LLM: the diagnostics probes are patched,
OAuth uses fake client credentials and no connection row exists to revoke.
"""

from __future__ import annotations

import re
import typing
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.routing import Route

from admino import server
from admino.access import Capability, Principal, can
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    CLIENT_IP,
    MEMBER_ROLES,
    NEW_PASSWORD,
    PASSWORD,
    PENDING_CAPABILITIES,
    PROJECT_ROLES,
    PROJECT_ROLES_PENDING,
    ROLE_MATRIX,
    ROLES,
    ROUTES,
    SERVICE_CAPABILITIES,
    UNAUTHORIZED,
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
    seed_failed_chat,
    seed_pending_confirmation,
    stub_agent,
    upload_headers,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant
    from fastapi.testclient import TestClient

_CATALOG_FILE: Final = "tests/tenancy_world.py"
_CHAT_ID: Final = "tenancy-163"
_CONFIRMATION_ID: Final = "confirm-163"
_SMUGGLED_FIELDS: Final = ("org_id", "user_id")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B with an Org Admin, an Editor and a Viewer each, plus a Super Admin.

    The FakeDb backs ``admino.database.get_pool()``; passwords hash fast; every
    rate bucket is roomy (the rate-limit tests read the bucket keys, not the
    limits). OAuth has fake client credentials, and the diagnostics probes
    (database health, LLM reachability) are patched so nothing leaves the host.
    GH-187: attachments live under ``tmp_path`` and both orgs have a storage quota.
    """
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "fake-google-client-id-gh163")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "fake-google-client-secret-gh163")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "fake-microsoft-client-id-gh163")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "fake-microsoft-client-secret-gh163")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "https://admino.example.ch/api/oauth/callback")
    monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
    monkeypatch.setattr("admino.server._check_llm_reachable", AsyncMock(return_value=True))
    return built


@pytest.fixture()
def agent() -> MagicMock:
    """A stub agent; its ``run`` is an AsyncMock that answers a final reply."""
    return stub_agent()


@pytest.fixture()
def app(world: World, agent: MagicMock) -> FastAPI:
    """The app, built after the world (create_app clears the server's in-memory state)."""
    return make_app(agent)


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    """A client at the world's client IP."""
    return make_client(app)


# ---------------------------------------------------------------------------
# Requests: one well-formed request per catalog row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Request:
    """A request to send: method, concrete URL, JSON body and query parameters, and
    (GH-187's upload) a raw body with its request headers."""

    method: str
    url: str
    json: dict[str, Any] | None = None
    params: dict[str, str] | None = None
    content: bytes | None = None
    headers: dict[str, str] | None = None


# (world, caller, client) -> the request. A builder may seed what the request
# needs (a second session, a pending invitation, a pending confirmation...).
_Builder = Callable[[World, Account, "TestClient"], _Request]


def _plain(
    method: str,
    url: str,
    json: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> _Builder:
    """A builder for a request that needs no setup."""

    def build(_world: World, _caller: Account, _client: TestClient) -> _Request:
        return _Request(method, url, json, params)

    return build


def _own_second_session(world: World, caller: Account, _client: TestClient) -> _Request:
    """DELETE /api/me/sessions/{id} on the caller's own second session."""
    token = world.db.open_session(caller.user_id)
    return _Request("DELETE", f"/api/me/sessions/{world.db.session_id_of(token)}")


def _org_user_logout(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Force logout of org A's Viewer."""
    return _Request("POST", f"/api/org/users/{world.a['viewer'].user_id}/logout")


def _org_a_member(world: World, *, status: str = "active") -> str:
    """Seed a fresh Editor of org A (never the last Org Admin); return its id."""
    return str(
        world.db.add_account(
            role="editor",
            org_id=world.org_a,
            status=status,
            email=f"managed-{status}-164@example.ch",
        )
    )


def _org_user_patch(world: World, _caller: Account, _client: TestClient) -> _Request:
    """PATCH org A's Viewer to Editor (GH-164)."""
    return _Request("PATCH", f"/api/org/users/{world.a['viewer'].user_id}", {"role": "editor"})


def _org_user_deactivate(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Deactivate org A's (active) Viewer."""
    return _Request("POST", f"/api/org/users/{world.a['viewer'].user_id}/deactivate")


def _org_user_reactivate(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Reactivate a deactivated Editor of org A (seats are free)."""
    return _Request(
        "POST", f"/api/org/users/{_org_a_member(world, status='deactivated')}/reactivate"
    )


def _org_user_delete(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Delete a fresh active Editor of org A."""
    return _Request("DELETE", f"/api/org/users/{_org_a_member(world)}")


def _org_user_password_reset(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Send org A's (active) Viewer a password reset link."""
    return _Request("POST", f"/api/org/users/{world.a['viewer'].user_id}/password-reset")


def _pending_invitation_id(world: World) -> str:
    """Seed a pending invitation in org A; return its id."""
    invited = world.db.add_account(
        role="editor",
        org_id=world.org_a,
        status="invited",
        password_hash=None,
        email="pending-invitee-163@example.ch",
    )
    world.db.add_invitation(invited)
    row = world.db.invitation_of(invited)
    assert row is not None
    return str(row["id"])


def _revoke_invitation(world: World, _caller: Account, _client: TestClient) -> _Request:
    """DELETE a pending invitation of org A."""
    return _Request("DELETE", f"/api/org/invitations/{_pending_invitation_id(world)}")


def _resend_invitation(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Resend a pending invitation of org A."""
    return _Request("POST", f"/api/org/invitations/{_pending_invitation_id(world)}/resend")


def _cancel_pending_promotion(world: World, _caller: Account, client: TestClient) -> _Request:
    """Cancel org A's pending gmail.send promotion (org A's Org Admin starts it first)."""
    admin = world.a["org_admin"]
    started = client.patch(
        "/api/org/critical-permissions/gmail/send",
        headers=admin.cookie,
        json={"password": PASSWORD},
    )
    assert started.status_code == 200, started.text
    return _Request("DELETE", "/api/org/critical-permissions/gmail/send/pending")


def _chat_owner(world: World, caller: Account) -> Account:
    """The caller, or org A's Editor for the Super Admin (who can own no chat)."""
    return caller if caller.org_id is not None else world.a["editor"]


def _confirm(world: World, caller: Account, _client: TestClient) -> _Request:
    """Approve a pending confirmation seeded in the caller's own legacy chat (GH-176: a
    persisted chat with that legacy session id, the pending in the chat runtime)."""
    owner = _chat_owner(world, caller)
    chat_id = seed_chat(world.db, owner, legacy_session_id=_CHAT_ID)
    seed_pending_confirmation(owner, chat_id, _CONFIRMATION_ID)
    return _Request(
        "POST",
        f"/api/confirm/{_CONFIRMATION_ID}",
        json={"session_id": _CHAT_ID, "confirmation_id": _CONFIRMATION_ID, "approved": True},
    )


def _own_chat(
    method: str, suffix: str = "", json: dict[str, Any] | None = None, *, history: bool = True
) -> _Builder:
    """A request on a chat of the caller's own (GH-176), titled and, with ``history``,
    holding a question and its answer (an empty chat for a new turn)."""

    def build(world: World, caller: Account, _client: TestClient) -> _Request:
        chat_id = seed_chat(
            world.db,
            _chat_owner(world, caller),
            title="Tenancy chat 176",
            messages=(("user", "Tenancy question 176"), ("assistant", "Tenancy answer 176"))
            if history
            else (),
        )
        return _Request(method, f"/api/chats/{chat_id}{suffix}", json)

    return build


def _own_failed_chat(world: World, caller: Account, _client: TestClient) -> _Request:
    """GH-245: retry (no body) a chat of the caller's own whose one turn failed (the
    answer stored ``error``): the stub agent re-runs it and the route answers 200."""
    chat_id = seed_failed_chat(
        world.db,
        _chat_owner(world, caller),
        title="Tenancy chat 245",
        question="Tenancy question 245",
        answer="Tenancy failed answer 245",
    )
    return _Request("POST", f"/api/chats/{chat_id}/retry")


def _own_chat_upload(world: World, caller: Account, _client: TestClient) -> _Request:
    """GH-187: upload a short text file into a chat of the caller's own."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Tenancy chat 187")
    return _Request(
        "POST",
        f"/api/chats/{chat_id}/attachments",
        content=UPLOAD_BODY,
        headers=upload_headers(),
    )


def _own_attachment(suffix: str) -> _Builder:
    """GH-187: read (``suffix`` "") or download ("/content") an attachment of a chat of
    the caller's own, its file stored under the attachments root."""

    def build(world: World, caller: Account, _client: TestClient) -> _Request:
        chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Tenancy chat 187")
        return _Request("GET", f"/api/attachments/{seed_attachment(world.db, chat_id)}{suffix}")

    return build


def _exclude_own_attachment(world: World, caller: Account, _client: TestClient) -> _Request:
    """GH-190: exclude (``{"active": false}``) an attachment of a chat of the caller's own."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Tenancy chat 190")
    attachment_id = seed_attachment(world.db, chat_id)
    return _Request("PATCH", f"/api/attachments/{attachment_id}", {"active": False})


def _list_own_chat_attachments(world: World, caller: Account, _client: TestClient) -> _Request:
    """GH-190: list the files of a chat of the caller's own (it holds one)."""
    chat_id = seed_chat(world.db, _chat_owner(world, caller), title="Tenancy chat 190")
    seed_attachment(world.db, chat_id)
    return _Request("GET", f"/api/chats/{chat_id}/attachments")


def _platform_org(method: str, suffix: str, json: dict[str, Any] | None = None) -> _Builder:
    """A platform request on org A's path."""

    def build(world: World, _caller: Account, _client: TestClient) -> _Request:
        return _Request(method, f"/api/platform/orgs/{world.org_a}{suffix}", json)

    return build


def _platform_org_user(action: str, target: Callable[[World], str]) -> _Builder:
    """A Super Admin action on one of org A's accounts, on org A's path (GH-167)."""

    def build(world: World, _caller: Account, _client: TestClient) -> _Request:
        return _Request("POST", f"/api/platform/orgs/{world.org_a}/users/{target(world)}/{action}")

    return build


def _org_a_viewer(world: World) -> str:
    """Org A's active Viewer (never the org's last Org Admin)."""
    return str(world.a["viewer"].user_id)


def _org_a_deactivated(world: World) -> str:
    """A fresh deactivated Editor of org A (org A has free seats)."""
    return _org_a_member(world, status="deactivated")


def _platform_reinvite(world: World, _caller: Account, _client: TestClient) -> _Request:
    """Resend (the empty body) the invitation of a fresh org whose first Org Admin is
    still invited, so the org has no active Org Admin (GH-167)."""
    org_id = world.db.add_org(name="Org C of GH-167")
    invited = world.db.add_account(
        role="org_admin",
        org_id=org_id,
        status="invited",
        name=None,
        password_hash=None,
        email="org-c-first-admin-167@example.ch",
    )
    world.db.add_invitation(invited)
    return _Request("POST", f"/api/platform/orgs/{org_id}/users/{invited}/invitation", {})


_TOKEN_163: Final = "invitation-or-reset-token-of-gh163-not-a-real-one-xx"

# Every catalog row: a request that passes request validation for the route
# (the handler may still answer 404/409 for one without seeded data).
_REQUESTS: Final[dict[tuple[str, str], _Builder]] = {
    # --- public ---
    ("GET", "/health"): _plain("GET", "/health"),
    ("POST", "/api/auth/login"): _plain(
        "POST",
        "/api/auth/login",
        {"email": "nobody-163@example.ch", "password": "not-the-password-163"},
    ),
    ("POST", "/api/auth/password-reset"): _plain(
        "POST", "/api/auth/password-reset", {"email": "nobody-163@example.ch"}
    ),
    ("POST", "/api/auth/password-reset/confirm"): _plain(
        "POST",
        "/api/auth/password-reset/confirm",
        {"token": _TOKEN_163, "new_password": "A-new-password-163-quartz"},
    ),
    ("GET", "/api/auth/invitations/{token}"): _plain("GET", f"/api/auth/invitations/{_TOKEN_163}"),
    ("POST", "/api/auth/invitations/{token}/accept"): _plain(
        "POST",
        f"/api/auth/invitations/{_TOKEN_163}/accept",
        {"name": "Someone New", "password": "A-new-password-163-quartz"},
    ),
    ("GET", "/api/oauth/callback"): _plain(
        "GET", "/api/oauth/callback", params={"code": "code-163", "state": "state-163"}
    ),
    # --- own account ---
    ("POST", "/api/auth/logout"): _plain("POST", "/api/auth/logout"),
    ("GET", "/api/auth/me"): _plain("GET", "/api/auth/me"),
    ("GET", "/api/me/sessions"): _plain("GET", "/api/me/sessions"),
    ("DELETE", "/api/me/sessions/{session_id}"): _own_second_session,
    ("GET", "/api/me/settings"): _plain("GET", "/api/me/settings"),
    ("PATCH", "/api/me/settings"): _plain(
        "PATCH", "/api/me/settings", {"appearance": {"theme": "dark"}}
    ),
    ("POST", "/api/me/settings/reset"): _plain("POST", "/api/me/settings/reset"),
    ("GET", "/api/me"): _plain("GET", "/api/me"),
    ("PATCH", "/api/me"): _plain("PATCH", "/api/me", {"timezone": "Europe/Zurich"}),
    # A real change (204): it ends the caller's sessions, but every test builds its own
    # world and sends this request once.
    ("POST", "/api/me/password"): _plain(
        "POST", "/api/me/password", {"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    ),
    # --- org users and invitations ---
    ("GET", "/api/org/users"): _plain("GET", "/api/org/users"),
    ("PATCH", "/api/org/users/{user_id}"): _org_user_patch,
    ("POST", "/api/org/users/{user_id}/deactivate"): _org_user_deactivate,
    ("POST", "/api/org/users/{user_id}/reactivate"): _org_user_reactivate,
    ("DELETE", "/api/org/users/{user_id}"): _org_user_delete,
    ("POST", "/api/org/users/{user_id}/password-reset"): _org_user_password_reset,
    ("POST", "/api/org/users/{user_id}/logout"): _org_user_logout,
    ("POST", "/api/org/invitations"): _plain(
        "POST", "/api/org/invitations", {"email": "new-invitee-163@example.ch", "role": "editor"}
    ),
    ("GET", "/api/org/invitations"): _plain("GET", "/api/org/invitations"),
    ("DELETE", "/api/org/invitations/{invitation_id}"): _revoke_invitation,
    ("POST", "/api/org/invitations/{invitation_id}/resend"): _resend_invitation,
    # --- org settings and tool permissions ---
    ("GET", "/api/org/settings"): _plain("GET", "/api/org/settings"),
    ("PATCH", "/api/org/settings"): _plain(
        "PATCH", "/api/org/settings", {"tools": {"gmail": False}}
    ),
    ("GET", "/api/org/permissions"): _plain("GET", "/api/org/permissions"),
    ("PATCH", "/api/org/permissions"): _plain(
        "PATCH",
        "/api/org/permissions",
        {"tool": "gmail", "action": "read", "permission": "confirm"},
    ),
    ("GET", "/api/org/critical-permissions"): _plain("GET", "/api/org/critical-permissions"),
    ("PATCH", "/api/org/critical-permissions/{tool}/{action}"): _plain(
        "PATCH", "/api/org/critical-permissions/gmail/send", {"password": PASSWORD}
    ),
    (
        "DELETE",
        "/api/org/critical-permissions/{tool}/{action}/pending",
    ): _cancel_pending_promotion,
    ("GET", "/api/permissions/summary"): _plain("GET", "/api/permissions/summary"),
    # --- chat ---
    ("POST", "/api/message"): _plain(
        "POST", "/api/message", {"message": "Hello from the tenancy suite", "session_id": _CHAT_ID}
    ),
    ("POST", "/api/confirm/{confirmation_id}"): _confirm,
    # GH-176: persisted chats ({} is a valid create body: no title, "auto").
    ("POST", "/api/chats"): _plain("POST", "/api/chats", {}),
    ("GET", "/api/chats"): _plain("GET", "/api/chats"),
    ("GET", "/api/chats/{chat_id}"): _own_chat("GET"),
    ("PATCH", "/api/chats/{chat_id}"): _own_chat("PATCH", json={"title": "Renamed chat 176"}),
    ("DELETE", "/api/chats/{chat_id}"): _own_chat("DELETE"),
    ("POST", "/api/chats/{chat_id}/messages"): _own_chat(
        "POST", "/messages", {"message": "Hello from the tenancy suite"}, history=False
    ),
    # GH-8: no request body; the caller's own idle chat answers 200 {"stopped": false}.
    ("POST", "/api/chats/{chat_id}/stop"): _own_chat("POST", "/stop"),
    # GH-245: no request body; the caller's own chat with a failed turn (200, re-run).
    ("POST", "/api/chats/{chat_id}/retry"): _own_failed_chat,
    # GH-187: a raw-body upload (no JSON body) and the two attachment reads.
    ("POST", "/api/chats/{chat_id}/attachments"): _own_chat_upload,
    ("GET", "/api/attachments/{attachment_id}"): _own_attachment(""),
    ("GET", "/api/attachments/{attachment_id}/content"): _own_attachment("/content"),
    # GH-190: exclude an attachment (a JSON body); list a chat's attachments.
    ("PATCH", "/api/attachments/{attachment_id}"): _exclude_own_attachment,
    ("GET", "/api/chats/{chat_id}/attachments"): _list_own_chat_attachments,
    # --- own Google/Microsoft connections ---
    ("GET", "/api/oauth/google/authorize"): _plain("GET", "/api/oauth/google/authorize"),
    ("GET", "/api/oauth/microsoft/authorize"): _plain("GET", "/api/oauth/microsoft/authorize"),
    ("GET", "/api/oauth/google/status"): _plain("GET", "/api/oauth/google/status"),
    ("GET", "/api/oauth/microsoft/status"): _plain("GET", "/api/oauth/microsoft/status"),
    ("DELETE", "/api/oauth/google"): _plain("DELETE", "/api/oauth/google"),
    ("DELETE", "/api/oauth/microsoft"): _plain("DELETE", "/api/oauth/microsoft"),
    # --- platform ---
    ("GET", "/api/platform/orgs"): _plain("GET", "/api/platform/orgs"),
    ("POST", "/api/platform/orgs"): _plain(
        "POST",
        "/api/platform/orgs",
        {
            "name": "Org C of GH-163",
            "primary_admin_email": "org-c-admin-163@example.ch",
            "seats": 5,
            "monthly_budget_chf": 100,
            "storage_quota": 1_073_741_824,
        },
    ),
    ("PATCH", "/api/platform/orgs/{org_id}/limits"): _platform_org(
        "PATCH", "/limits", {"seats": 50}
    ),
    ("POST", "/api/platform/orgs/{org_id}/deactivate"): _platform_org("POST", "/deactivate"),
    ("POST", "/api/platform/orgs/{org_id}/reactivate"): _platform_org("POST", "/reactivate"),
    ("POST", "/api/platform/orgs/{org_id}/deletion"): _platform_org("POST", "/deletion"),
    ("DELETE", "/api/platform/orgs/{org_id}/deletion"): _platform_org("DELETE", "/deletion"),
    ("PATCH", "/api/platform/orgs/{org_id}/residency"): _platform_org(
        "PATCH", "/residency", {"enabled": True}
    ),
    # GH-167: org A's accounts and metadata; the user actions on org A's accounts.
    ("GET", "/api/platform/orgs/{org_id}/users"): _platform_org("GET", "/users"),
    ("GET", "/api/platform/orgs/{org_id}/metadata"): _platform_org("GET", "/metadata"),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/deactivate"): _platform_org_user(
        "deactivate", _org_a_viewer
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/reactivate"): _platform_org_user(
        "reactivate", _org_a_deactivated
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/password-reset"): _platform_org_user(
        "password-reset", _org_a_viewer
    ),
    ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/invitation"): _platform_reinvite,
    ("GET", "/api/platform/diagnostics"): _plain("GET", "/api/platform/diagnostics"),
    ("GET", "/api/platform/settings"): _plain("GET", "/api/platform/settings"),
    ("PATCH", "/api/platform/settings"): _plain(
        "PATCH", "/api/platform/settings", {"limits": {"max_tool_calls_per_message": 20}}
    ),
}

# Every non-public route that takes a JSON body (the completeness test below
# compares this with the registered routes' body fields).
_BODY_ROUTES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("PATCH", "/api/me/settings"),
        ("PATCH", "/api/me"),
        ("POST", "/api/me/password"),
        ("PATCH", "/api/org/users/{user_id}"),
        ("POST", "/api/org/invitations"),
        ("PATCH", "/api/org/settings"),
        ("PATCH", "/api/org/permissions"),
        ("PATCH", "/api/org/critical-permissions/{tool}/{action}"),
        ("POST", "/api/message"),
        ("POST", "/api/confirm/{confirmation_id}"),
        # GH-176: create (a JSON body is required, {} is valid), rename, send.
        ("POST", "/api/chats"),
        ("PATCH", "/api/chats/{chat_id}"),
        ("POST", "/api/chats/{chat_id}/messages"),
        # GH-190: {"active": bool}.
        ("PATCH", "/api/attachments/{attachment_id}"),
        ("POST", "/api/platform/orgs"),
        ("PATCH", "/api/platform/orgs/{org_id}/limits"),
        ("PATCH", "/api/platform/orgs/{org_id}/residency"),
        ("PATCH", "/api/platform/settings"),
        # GH-167: the optional re-invite body (no body, {} or {"email": ...}).
        ("POST", "/api/platform/orgs/{org_id}/users/{user_id}/invitation"),
    }
)

_PUBLIC_SPECS: Final = [spec for spec in ROUTES if spec.audience == "public"]
_PROTECTED_SPECS: Final = [spec for spec in ROUTES if spec.audience != "public"]
_MEMBER_SPECS: Final = [spec for spec in ROUTES if spec.audience == "member"]
_BODY_SPECS: Final = [spec for spec in ROUTES if (spec.method, spec.path) in _BODY_ROUTES]


def _allowed_caller(world: World, spec: RouteSpec) -> Account:
    """An account allowed on ``spec``: org A's Editor, else its Org Admin, else the SA."""
    roles = allowed_roles(spec)
    if "editor" in roles:
        return world.a["editor"]
    if "org_admin" in roles:
        return world.a["org_admin"]
    assert "super_admin" in roles, route_id(spec)
    return world.super_admin


def _build(world: World, spec: RouteSpec, caller: Account, client: TestClient) -> _Request:
    """The well-formed request of ``spec`` for ``caller`` (seeding what it needs)."""
    return _REQUESTS[(spec.method, spec.path)](world, caller, client)


def _send(
    client: TestClient, request: _Request, headers: dict[str, str] | None = None
) -> httpx.Response:
    """Send ``request`` with its own headers plus ``headers`` (a session cookie, or none)."""
    return client.request(
        request.method,
        request.url,
        json=request.json,
        params=request.params,
        content=request.content,
        headers={**(request.headers or {}), **(headers or {})},
    )


# ---------------------------------------------------------------------------
# Route walking
# ---------------------------------------------------------------------------


def _api_routes(app: FastAPI) -> dict[tuple[str, str], APIRoute]:
    """(method, path) -> APIRoute for every registered API route."""
    return {
        (method, route.path): route
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in sorted(route.methods)
    }


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _models_in(annotation: Any) -> list[type[BaseModel]]:
    """The Pydantic models inside a type: itself, or inside list/Optional/union/Annotated."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    found: list[type[BaseModel]] = []
    for arg in typing.get_args(annotation):
        found.extend(_models_in(arg))
    return found


def _model_tree(roots: list[type[BaseModel]]) -> list[type[BaseModel]]:
    """Every model reachable from ``roots`` through field annotations (each once)."""
    seen: list[type[BaseModel]] = []
    pending = list(roots)
    while pending:
        model = pending.pop()
        if model in seen:
            continue
        seen.append(model)
        for field in model.model_fields.values():
            pending.extend(_models_in(field.annotation))
    return seen


def _body_annotation(route: APIRoute) -> Any:
    """The declared type of a route's JSON body."""
    assert route.body_field is not None
    return route.body_field.field_info.annotation


def _writes_since(db: FakeDb, mark: int) -> list[str]:
    """Data-changing statements since call ``mark``, except the session refresh."""
    return [
        call.normalized
        for call in db.calls[mark:]
        if re.search(r"\b(?:insert\s+into|delete\s+from|update\s+\w+\s+set)\b", call.normalized)
        and not re.match(r"^update sessions\b", call.normalized)
    ]


# ---------------------------------------------------------------------------
# 1. The world (AC "Fixtures")
# ---------------------------------------------------------------------------


class TestWorld:
    """Two orgs x (Org Admin, Editor, Viewer), plus a Super Admin."""

    def test_tenancy_world_has_seven_distinct_accounts(self, world: World) -> None:
        """Exactly the seven accounts, each with its own id, email and token."""
        accounts = world.everyone()

        assert (
            len(accounts),
            len({a.user_id for a in accounts}),
            len({a.email for a in accounts}),
            len({a.token for a in accounts}),
            len(world.db.users),
        ) == (7, 7, 7, 7, 7)

    def test_tenancy_world_has_two_distinct_orgs(self, world: World) -> None:
        """Org A and org B are different organizations, both stored."""
        assert world.org_a != world.org_b
        assert set(world.db.orgs) == {world.org_a, world.org_b}

    def test_tenancy_world_members_belong_to_their_org_with_their_role(self, world: World) -> None:
        """Each org has one account per member role; the SA has no org."""
        assert {role: (acct.org_id, acct.role) for role, acct in world.a.items()} == {
            role: (world.org_a, role) for role in MEMBER_ROLES
        }
        assert {role: (acct.org_id, acct.role) for role, acct in world.b.items()} == {
            role: (world.org_b, role) for role in MEMBER_ROLES
        }
        assert (world.super_admin.org_id, world.super_admin.role) == (None, "super_admin")

    def test_tenancy_world_every_token_resolves_to_its_account(
        self, world: World, client: TestClient
    ) -> None:
        """GET /api/auth/me with each account's cookie answers that account's ids."""
        seen: dict[str, tuple[int, Any]] = {}
        expected: dict[str, tuple[int, Any]] = {}
        for account in world.everyone():
            response = client.get("/api/auth/me", headers=account.cookie)
            body = response.json() if response.status_code == 200 else response.text
            kind = "super_admin" if account.role == "super_admin" else "member"
            role = None if account.role == "super_admin" else account.role
            org = None if account.org_id is None else str(account.org_id)
            seen[account.email] = (
                response.status_code,
                (body["user_id"], body["kind"], body["org_id"], body["role"])
                if isinstance(body, dict)
                else body,
            )
            expected[account.email] = (200, (str(account.user_id), kind, org, role))

        assert seen == expected

    def test_tenancy_world_role_lookup_returns_org_a_or_the_super_admin(self, world: World) -> None:
        """by_role() serves the role tests: the SA, or org A's account with that role."""
        assert [world.by_role(role).role for role in ROLES] == list(ROLES)
        assert {world.by_role(role).org_id for role in MEMBER_ROLES} == {world.org_a}


# ---------------------------------------------------------------------------
# 2. Route enumeration and catalog completeness (AC "Route enumeration")
# ---------------------------------------------------------------------------


class TestRouteEnumeration:
    """Every registered route is catalogued, and every non-public one needs a session."""

    def test_tenancy_every_registered_route_has_a_catalog_row(self, app: FastAPI) -> None:
        """A new route fails here until it gets a RouteSpec row (and its cases)."""
        catalog = {(spec.method, spec.path) for spec in ROUTES}
        missing = sorted(set(_api_routes(app)) - catalog)

        assert missing == [], (
            f"Registered routes without a RouteSpec row in {_CATALOG_FILE} ROUTES: {missing}. "
            "Add the row, then the route's role, cross-org and request cases in the "
            "tests/test_tenancy*.py files."
        )

    def test_tenancy_every_catalog_row_is_a_registered_route(self, app: FastAPI) -> None:
        """No stale row: each RouteSpec names a registered (method, path)."""
        stale = sorted({(spec.method, spec.path) for spec in ROUTES} - set(_api_routes(app)))

        assert stale == [], f"Rows in {_CATALOG_FILE} ROUTES with no registered route: {stale}"

    def test_tenancy_catalog_has_no_duplicate_rows(self) -> None:
        """Each (method, path) has exactly one row."""
        keys = [(spec.method, spec.path) for spec in ROUTES]

        assert sorted(key for key in set(keys) if keys.count(key) > 1) == []

    def test_tenancy_every_non_public_route_depends_on_require_session(self, app: FastAPI) -> None:
        """server.require_session is in the dependency tree of every registered route
        outside the public allowlist, catalogued or not."""
        public = {(spec.method, spec.path) for spec in _PUBLIC_SPECS}
        offenders = [
            f"{method} {path}"
            for (method, path), route in sorted(_api_routes(app).items())
            if (method, path) not in public
            and not _depends_on(route.dependant, server.require_session)
        ]

        assert offenders == []

    def test_tenancy_public_routes_do_not_depend_on_require_session(self, app: FastAPI) -> None:
        """/health, the login, reset and invitation link routes and the OAuth callback
        work logged out."""
        routes = _api_routes(app)
        offenders = [
            route_id(spec)
            for spec in _PUBLIC_SPECS
            if _depends_on(routes[(spec.method, spec.path)].dependant, server.require_session)
        ]

        assert offenders == []

    def test_tenancy_public_allowlist_is_the_tracker_list(self) -> None:
        """#139 §5: only /health, login, reset, invitation link routes and the OAuth
        callback (plus static files) are public."""
        assert sorted(route_id(spec) for spec in _PUBLIC_SPECS) == sorted(
            [
                "GET /health",
                "POST /api/auth/login",
                "POST /api/auth/password-reset",
                "POST /api/auth/password-reset/confirm",
                "GET /api/auth/invitations/{token}",
                "POST /api/auth/invitations/{token}/accept",
                "GET /api/oauth/callback",
            ]
        )

    @pytest.mark.parametrize("spec", _PROTECTED_SPECS, ids=route_id)
    def test_tenancy_non_public_route_answers_401_without_a_session(
        self, spec: RouteSpec, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """No cookie: exactly 401 Unauthorized, and the agent never runs."""
        request = _build(world, spec, world.a["org_admin"], client)

        response = _send(client, request)

        assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
        agent.run.assert_not_awaited()

    def test_tenancy_no_plain_route_is_reachable_without_a_session(
        self, client: TestClient, app: FastAPI
    ) -> None:
        """A non-API Starlette route (e.g. an OpenAPI schema) answers 401 logged out.
        Static files are served by a Mount and stay public."""
        offenders: list[str] = []
        for route in app.routes:
            if not isinstance(route, Route) or isinstance(route, APIRoute):
                continue
            for method in sorted((route.methods or {"GET"}) - {"HEAD"}):
                status = client.request(method, route.path).status_code
                if status != 401:
                    offenders.append(f"{method} {route.path}: {status}")

        assert offenders == []

    def test_tenancy_every_catalog_row_has_a_request(self) -> None:
        """Each ROUTES row has a well-formed request in _REQUESTS (this file)."""
        assert sorted(set(_REQUESTS) ^ {(spec.method, spec.path) for spec in ROUTES}) == []

    def test_tenancy_body_route_list_matches_the_registered_body_fields(self, app: FastAPI) -> None:
        """_BODY_ROUTES lists exactly the non-public routes that take a JSON body."""
        protected = {(spec.method, spec.path) for spec in _PROTECTED_SPECS}
        with_body = {
            key
            for key, route in _api_routes(app).items()
            if key in protected and route.body_field is not None
        }

        assert sorted(with_body ^ _BODY_ROUTES) == []


class TestCatalogConsistency:
    """The catalog is internally consistent with #139 §2.1 and access.can."""

    def test_tenancy_role_matrix_covers_every_capability(self) -> None:
        """ROLE_MATRIX has one entry per Capability, no more, no less."""
        assert sorted(set(Capability) ^ set(ROLE_MATRIX)) == []

    def test_tenancy_every_capability_is_routed_xor_pending(self) -> None:
        """A capability has a route (a ROUTES row, or a route's service in
        SERVICE_CAPABILITIES) or a pending issue, never both, never neither."""
        routed = {spec.capability for spec in ROUTES if spec.capability is not None}
        routed |= set(SERVICE_CAPABILITIES)
        offenders = [
            f"{cap.value}: routed={cap in routed} pending={cap in PENDING_CAPABILITIES}"
            for cap in Capability
            if (cap in routed) == (cap in PENDING_CAPABILITIES)
        ]

        assert offenders == [], (
            f"Each capability must be routed (a ROUTES row) xor in PENDING_CAPABILITIES "
            f"({_CATALOG_FILE}); move it out of PENDING_CAPABILITIES when its route lands."
        )

    def test_tenancy_no_route_uses_a_pending_capability(self) -> None:
        """A routed capability is no longer pending."""
        assert [route_id(spec) for spec in ROUTES if spec.capability in PENDING_CAPABILITIES] == []

    def test_tenancy_service_capability_routes_are_catalog_rows(self) -> None:
        """Each SERVICE_CAPABILITIES entry names at least one route, and every route it
        names is a ROUTES row (its role cases run on that row)."""
        rows = {(spec.method, spec.path) for spec in ROUTES}
        offenders = {
            cap.value: sorted(set(routes) - rows)
            for cap, routes in SERVICE_CAPABILITIES.items()
            if not routes or not set(routes) <= rows
        }

        assert offenders == {}

    def test_tenancy_service_capabilities_share_their_routes_roles(self) -> None:
        """A service capability has exactly the roles of each route that checks it, so the
        role cases of the route (tests/test_tenancy_roles.py) cover it too."""
        specs = {(spec.method, spec.path): spec for spec in ROUTES}
        offenders = [
            f"{cap.value} on {method} {path}: {sorted(ROLE_MATRIX[cap])} != "
            f"{sorted(allowed_roles(specs[(method, path)]))}"
            for cap, routes in SERVICE_CAPABILITIES.items()
            for method, path in routes
            if (method, path) in specs
            and set(ROLE_MATRIX[cap]) != set(allowed_roles(specs[(method, path)]))
        ]

        assert offenders == []

    def test_tenancy_no_service_capability_is_pending(self) -> None:
        """A capability checked by a routed service is no longer pending its issue."""
        assert sorted(set(SERVICE_CAPABILITIES) & set(PENDING_CAPABILITIES)) == []

    def test_tenancy_pending_capabilities_name_their_issue(self) -> None:
        """Each pending capability names the issue that adds its route (e.g. "#185")."""
        assert [
            cap.value
            for cap, issue in PENDING_CAPABILITIES.items()
            if not re.fullmatch(r"#\d+", issue)
        ] == []

    @pytest.mark.parametrize("capability", list(Capability), ids=lambda cap: cap.value)
    def test_tenancy_role_matrix_agrees_with_access_can(self, capability: Capability) -> None:
        """The spelled-out §2.1 matrix and access.can agree for every role (drift either
        way fails)."""
        principals: dict[Role, Principal] = {
            "super_admin": Principal(user_id=uuid.uuid4(), kind="super_admin"),
            **{
                role: Principal(user_id=uuid.uuid4(), kind="member", org_id=uuid.uuid4(), role=role)
                for role in MEMBER_ROLES
            },
        }

        assert {role for role, principal in principals.items() if can(principal, capability)} == (
            set(ROLE_MATRIX[capability])
        )

    def test_tenancy_audiences_match_their_capabilities(self) -> None:
        """Public rows are ungated; account rows admit the SA; member rows refuse the SA;
        platform rows admit the SA only."""
        offenders: list[str] = []
        for spec in ROUTES:
            roles = allowed_roles(spec)
            ok = {
                "public": spec.capability is None,
                "account": "super_admin" in roles,
                "member": "super_admin" not in roles and bool(roles),
                "platform": roles == frozenset({"super_admin"}),
            }[spec.audience]
            if not ok:
                offenders.append(f"{route_id(spec)} ({spec.audience}): {sorted(roles)}")

        assert offenders == []

    def test_tenancy_isolation_kinds_match_audiences(self) -> None:
        """Public and platform rows hold no tenant content ("none"); account and member
        rows always say how they are isolated."""
        offenders = [
            route_id(spec)
            for spec in ROUTES
            if (spec.isolation == "none") != (spec.audience in {"public", "platform"})
        ]

        assert offenders == []


class TestProjectRoles:
    """#139 §2.2 project roles: pending until project routes exist."""

    def test_tenancy_no_project_route_exists_while_project_roles_are_pending(
        self, app: FastAPI
    ) -> None:
        """Tripwire: the first /api/projects route must bring the §2.2 HTTP cases."""
        project_routes = sorted(
            f"{method} {path}"
            for method, path in _api_routes(app)
            if path.startswith("/api/projects")
        )

        assert PROJECT_ROLES_PENDING
        assert project_routes == [], (
            f"Project routes exist ({project_routes}): add the #139 §2.2 project-role HTTP "
            f"cases for PROJECT_ROLES and retire PROJECT_ROLES_PENDING in {_CATALOG_FILE}."
        )

    def test_tenancy_project_roles_are_the_five_tracker_rows(self) -> None:
        """PROJECT_ROLES lists exactly the five §2.2 rows."""
        assert list(PROJECT_ROLES) == [
            (
                "Read all chats in the project",
                frozenset({"owner", "project_editor", "project_viewer"}),
            ),
            (
                "Create chats and send messages in their own chats",
                frozenset({"owner", "project_editor"}),
            ),
            ("Upload files", frozenset({"owner", "project_editor"})),
            ("Edit the project's instructions", frozenset({"owner", "project_editor"})),
            ("Share, change member roles, transfer, delete", frozenset({"owner"})),
        ]


# ---------------------------------------------------------------------------
# 3. Operator blindness (AC "Operator blindness")
# ---------------------------------------------------------------------------


_CONTENT_FIELD: Final = re.compile(r"(?:^|_)(?:title|name|content|file_?name)s?(?:$|_)")
# (model, field) pairs allowed on platform responses: the org name and user
# account metadata (#139 §5): a user's name in the Super Admin's users list
# (GH-167). Each entry must actually be encountered.
_PLATFORM_FIELD_ALLOWLIST: Final[frozenset[tuple[str, str]]] = frozenset(
    {("OrgSummary", "name"), ("PlatformUserSummary", "name")}
)
# Platform routes that answer an empty body (no response model): a 204, or the
# 202 of a Super Admin-triggered password reset (GH-167).
_EMPTY_BODY_STATUSES: Final = frozenset({202, 204})


class TestOperatorBlindness:
    """The Super Admin reaches no content route and no content field."""

    @pytest.mark.parametrize("spec", _MEMBER_SPECS, ids=route_id)
    def test_tenancy_super_admin_is_refused_on_every_member_route(
        self, spec: RouteSpec, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """403 or 404 with a bare ``{"detail": "<text>"}`` body, and no agent run."""
        request = _build(world, spec, world.super_admin, client)

        response = _send(client, request, world.super_admin.cookie)

        body = response.json()
        assert response.status_code in {403, 404}, response.text
        assert isinstance(body, dict)
        assert list(body) == ["detail"]
        assert isinstance(body["detail"], str)
        agent.run.assert_not_awaited()

    def test_tenancy_platform_responses_have_no_content_fields(self, app: FastAPI) -> None:
        """Platform response models (walked through nested models, lists and unions)
        have no title/name/content/file name field except the allowlisted org name and
        user name (account metadata); a route without a model answers 202 or 204."""
        roots: list[type[BaseModel]] = []
        undeclared: list[str] = []
        for (method, path), route in _api_routes(app).items():
            if not path.startswith("/api/platform/"):
                continue
            models = _models_in(route.response_model)
            if not models and route.status_code not in _EMPTY_BODY_STATUSES:
                undeclared.append(f"{method} {path}")
            roots.extend(models)
        tree = _model_tree(roots)
        fields = {(model.__name__, name) for model in tree for name in model.model_fields}
        content = sorted(
            pair
            for pair in fields
            if _CONTENT_FIELD.search(pair[1]) and pair not in _PLATFORM_FIELD_ALLOWLIST
        )

        assert undeclared == [], "platform routes must declare a Pydantic response_model"
        assert len(tree) >= 5, [model.__name__ for model in tree]
        assert content == []
        assert sorted(_PLATFORM_FIELD_ALLOWLIST - fields) == [], "stale allowlist entries"

    def test_tenancy_content_field_pattern_matches_content_names(self) -> None:
        """The pattern itself: content names match, metadata names don't."""
        names = [
            "title",
            "name",
            "content",
            "filename",
            "file_name",
            "chat_titles",
            "project_name",
            "message_content",
            "email",
            "role",
            "anthropic_model",
            "status",
            "renamed_at",
        ]

        assert [name for name in names if _CONTENT_FIELD.search(name)] == [
            "title",
            "name",
            "content",
            "filename",
            "file_name",
            "chat_titles",
            "project_name",
            "message_content",
        ]


# ---------------------------------------------------------------------------
# 4. Request bodies forbid smuggled fields (#17 absorbed; user decision 2)
# ---------------------------------------------------------------------------


class TestRequestBodies:
    """A smuggled org_id / user_id in a body is a 422 that changes nothing."""

    @pytest.mark.parametrize("spec", _BODY_SPECS, ids=route_id)
    def test_tenancy_body_models_forbid_extra_fields(self, spec: RouteSpec, app: FastAPI) -> None:
        """The body model and every model nested in it have ``extra="forbid"``."""
        route = _api_routes(app)[(spec.method, spec.path)]
        models = _model_tree(_models_in(_body_annotation(route)))
        lax = sorted(
            model.__name__ for model in models if model.model_config.get("extra") != "forbid"
        )

        assert models
        assert lax == []

    @pytest.mark.parametrize("spec", _BODY_SPECS, ids=route_id)
    def test_tenancy_valid_body_is_accepted(
        self, spec: RouteSpec, world: World, client: TestClient
    ) -> None:
        """Control for the 422 cases: the same body without the extra field succeeds."""
        caller = _allowed_caller(world, spec)
        request = _build(world, spec, caller, client)

        response = _send(client, request, caller.cookie)

        assert response.status_code in {200, 201, 204}, response.text

    @pytest.mark.parametrize("field", _SMUGGLED_FIELDS)
    @pytest.mark.parametrize("spec", _BODY_SPECS, ids=route_id)
    def test_tenancy_smuggled_id_in_body_is_rejected_without_effect(
        self,
        spec: RouteSpec,
        field: str,
        world: World,
        client: TestClient,
        agent: MagicMock,
    ) -> None:
        """Another org's id (or another org's user id) in the body: 422 extra_forbidden,
        no agent run, no write besides the session refresh, the chat runtime (pending
        confirmations) unchanged, and the smuggled value not echoed."""
        caller = _allowed_caller(world, spec)
        request = _build(world, spec, caller, client)
        smuggled = str(world.org_b if field == "org_id" else world.b["editor"].user_id)
        assert request.json is not None
        tampered = _Request(
            request.method, request.url, {**request.json, field: smuggled}, request.params
        )
        runtime_before = chat_runtime_state(world.db)
        mark = len(world.db.calls)

        response = _send(client, tampered, caller.cookie)

        assert response.status_code == 422, response.text
        assert any(
            error.get("type") == "extra_forbidden" and error.get("loc", [])[-1:] == [field]
            for error in response.json()["detail"]
        ), response.text
        assert smuggled not in response.text
        agent.run.assert_not_awaited()
        assert _writes_since(world.db, mark) == []
        assert chat_runtime_state(world.db) == runtime_before


# ---------------------------------------------------------------------------
# 5. Rate limits are keyed per user (per IP on public routes) (#139 §5)
# ---------------------------------------------------------------------------


class TestRateLimitKeys:
    """No bucket is shared by all callers."""

    @pytest.mark.parametrize("spec", _PROTECTED_SPECS, ids=route_id)
    def test_tenancy_non_public_route_spends_a_per_user_bucket(
        self, spec: RouteSpec, world: World, client: TestClient
    ) -> None:
        """One request by an allowed caller creates a bucket keyed ``user:<id>`` and no
        other caller key (the unresolved-cookie IP budget aside)."""
        caller = _allowed_caller(world, spec)
        request = _build(world, spec, caller, client)
        server._rate_buckets.clear()

        response = _send(client, request, caller.cookie)

        user_key = f"user:{caller.user_id}"
        keys = list(server._rate_buckets)
        assert response.status_code not in {401, 403, 422, 429}, response.text
        assert [key for key in keys if key[1] == user_key] != [], keys
        assert [
            key for key in keys if key[1] != user_key and key[0] != server._SESSION_FAILURE_ROUTE
        ] == []

    @pytest.mark.parametrize("spec", _PUBLIC_SPECS, ids=route_id)
    def test_tenancy_public_route_spends_a_per_ip_bucket(
        self, spec: RouteSpec, world: World, client: TestClient
    ) -> None:
        """One anonymous request creates a bucket keyed by the client IP, none per user
        and none shared."""
        request = _build(world, spec, world.a["editor"], client)
        server._rate_buckets.clear()

        response = _send(client, request)

        keys = list(server._rate_buckets)
        assert response.status_code not in {422, 429}, response.text
        assert [key for key in keys if key[1] == f"ip:{CLIENT_IP}"] != [], keys
        assert [key for key in keys if key[1] != f"ip:{CLIENT_IP}"] == []


# ---------------------------------------------------------------------------
# 6. The upload refuses a cross-site request (GH-187, #139 §5 CSRF)
# ---------------------------------------------------------------------------


class TestAttachmentUploadCsrf:
    """POST /api/chats/{chat_id}/attachments changes state: a cross-site request is refused."""

    def test_tenancy_attachment_upload_refuses_a_cross_site_request_and_stores_nothing(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """A cross-site upload (``Sec-Fetch-Site: cross-site``) by the chat's owner is 403
        ``Cross-origin request refused``: no row, no audit event, no file under the
        attachments root. Control: the same request from the same origin is the 201."""
        caller = world.a["editor"]
        request = _own_chat_upload(world, caller, client)
        audit_before = len(world.db.audit_rows())

        refused = _send(client, request, {**caller.cookie, "Sec-Fetch-Site": "cross-site"})
        stored_after_refusal = (
            len(world.db.attachments),
            len(world.db.audit_rows()) - audit_before,
            attachment_files(),
        )
        accepted = _send(client, request, {**caller.cookie, "Sec-Fetch-Site": "same-origin"})

        assert (refused.status_code, refused.json()) == (
            403,
            {"detail": "Cross-origin request refused"},
        )
        assert stored_after_refusal == (0, 0, {})
        assert accepted.status_code == 201, accepted.text
        agent.run.assert_not_awaited()


# ---------------------------------------------------------------------------
# 7. The retry refuses a cross-site request (GH-245, #139 §5 CSRF)
# ---------------------------------------------------------------------------


class TestChatRetryCsrf:
    """POST /api/chats/{chat_id}/retry runs the agent and replaces the failed turn: a
    cross-site request is refused before anything runs (Decision 4: a send's CSRF check)."""

    def test_tenancy_chat_retry_refuses_a_cross_site_request_and_runs_nothing(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """A cross-site retry (``Sec-Fetch-Site: cross-site``) by the chat's owner is 403
        ``Cross-origin request refused``: no run, no write statement, the chat and its
        failed turn as they were. Control: the same request from the same origin re-runs
        the turn (200, one run)."""
        caller = world.a["editor"]
        request = _own_failed_chat(world, caller, client)
        chat_id = uuid.UUID(request.url.split("/")[3])
        chat_before = world.db.chat_row(chat_id)
        messages_before = world.db.messages_of(chat_id)
        mark = len(world.db.calls)

        refused = _send(client, request, {**caller.cookie, "Sec-Fetch-Site": "cross-site"})
        after_refusal = (
            world.db.chat_row(chat_id),
            world.db.messages_of(chat_id),
            _writes_since(world.db, mark),
            agent.run.await_count,
        )
        accepted = _send(client, request, {**caller.cookie, "Sec-Fetch-Site": "same-origin"})

        assert (refused.status_code, refused.json()) == (
            403,
            {"detail": "Cross-origin request refused"},
        )
        assert after_refusal == (chat_before, messages_before, [], 0)
        assert accepted.status_code == 200, accepted.text
        assert agent.run.await_count == 1
