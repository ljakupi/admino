"""Cross-org cases of the tenant isolation suite (GH-163, AC "Cross-org cases").

Org A's callers against org B's resources, through the real app, real session
cookies and the in-memory database of tests/db_fakes.py (the world of
tests/tenancy_world.py: two orgs, each with an Org Admin and an Editor, plus a
Super Admin):

- ``path_id`` routes (a resource id in the path, or the chat confirmation):
  another org's id answers 404 with exactly the body of an unknown id, never
  echoes the id, and changes nothing: no row, audit event, email, session,
  chat, chat message, pending confirmation in the chat runtime or OAuth state.
  A control shows the caller reaches its own org's resource, and org B still
  reaches its own.
- The chat routes of GH-176 (GET/PATCH/DELETE /api/chats/{chat_id} and POST
  /api/chats/{chat_id}/messages) and GH-8's POST /api/chats/{chat_id}/stop:
  org B's chat is ``404 {"detail": "Chat not found", "reason":
  "chat_not_found"}`` like an unknown id; B's row, messages and pending
  confirmation stay, no ``chat.delete`` row is written, the agent never runs
  and B's title and content never appear. Chats are private to their owner: a
  colleague's chat in the caller's own org (an Org Admin's, an Editor's) is
  the same 404, for an Org Admin too. The stop route answers
  ``200 {"stopped": false}`` on the caller's own idle chat (the control).
- GH-187's attachment routes: an upload (``POST /api/chats/{chat_id}/attachments``,
  a raw body) into org B's chat, a colleague's chat or an unknown id is the
  chat routes' ``chat_not_found`` 404 and stores nothing (no row, audit event
  or file under the attachments root, which ``_state`` includes). The
  metadata and download routes (``GET /api/attachments/{attachment_id}`` and
  ``.../content``) answer ``404 {"detail": "Attachment not found", "reason":
  "attachment_not_found"}`` for org B's attachment, a colleague's (for an Org
  Admin too: downloads are the chat owner's only) and an unknown id, never
  showing the file's name or bytes; the owner still reads it (the control).
- GH-190: ``PATCH /api/attachments/{attachment_id}`` (exclude) on org B's
  attachment, a colleague's or an unknown id is the same
  ``attachment_not_found`` 404 and leaves the row (its ``active`` flag
  included) and the audit log as they were; ``GET
  /api/chats/{chat_id}/attachments`` on org B's chat, a colleague's or an
  unknown id is the chat routes' ``chat_not_found`` 404 and never lists a file.
- GH-194's trash: ``POST /api/trash/chats/{chat_id}/restore``, ``POST
  /api/trash/attachments/{attachment_id}/restore``, ``DELETE
  /api/trash/chats/{chat_id}`` and ``DELETE /api/trash/attachments/{attachment_id}``
  on org B's trashed chat (with its messages and a file trashed with it) or
  org B's file trashed on its own answer the chat routes' ``chat_not_found``
  or ``attachment_not_found`` 404 exactly like an unknown id, and B's rows,
  files on disk (originals and derived ``<id>.d/``) and audit log stay; B's
  Editor still restores or deletes it afterwards. ``DELETE
  /api/attachments/{attachment_id}`` (move a live file to the trash) joins the
  attachment routes above (org B's, a colleague's, an unknown file: 404, the
  row stays live). ``GET /api/trash`` lists only the caller's own items and
  ``DELETE /api/trash`` purges only the caller's own (``own_user``); a
  colleague's trash and the role refusals are in tests/test_trash_isolation.py.
- GH-245: ``POST /api/chats/{chat_id}/retry`` (no body) on org B's chat, a
  colleague's (an Org Admin's, an Editor's; for an Org Admin too) or an
  unknown id is the chat routes' ``chat_not_found`` 404, also when that chat's
  last turn failed and its owner could retry it: nothing runs, the failed turn
  stays (its messages and their statuses), no statement deletes it. The control
  is a chat of the caller's own whose turn failed: the stub agent re-runs it (200),
  and org B's owner still retries its own after A's refusal.
- ``own_org`` routes: org B is seeded differently from org A; org A's caller
  reads and changes only org A (settings, tool permissions, critical
  promotions, the permission summary, invitations, the user list and its
  seat usage). GH-169: org A's profile, instructions, session policy and
  trash retention changes leave org B's org_settings row, organizations row
  (name, language) and sessions as they were, and are audited for org A only;
  org A's read never shows org B's name, instructions or policies, even with
  org B's id in the query.
- The org user routes of GH-164 (PATCH, deactivate, reactivate, DELETE,
  password reset): every kind of org B account (its last Org Admin, a member,
  a deactivated user, an invited account) is a 404 "User not found" for org
  A's Org Admin, never a 409 that would tell its state, and B's user keeps
  its row, sessions, connections, notes, settings, reset token, queued emails
  and in-memory state. The PATCH demotes to Editor (GH-306: a real role change
  that runs the last-admin guard): its controls act on a second Org Admin of
  the caller's org.
- ``own_user`` routes: only the caller's own data: sessions, settings, the
  account, logout, OAuth connections (and the data residency of the caller's
  own org), the chat list and chat creation (GH-176: the caller's org and
  ownership, a smuggled ``org_id`` / ``owner_user_id`` is a 422), and the
  legacy chat routes: a legacy ``session_id`` names the caller's own persisted
  chat (``chats.legacy_session_id``), so org B's session id creates or uses
  the caller's chat, never B's, and B's pending confirmation stays.
- The Super Admin's user routes of GH-167 (deactivate, reactivate, password
  reset and re-invite under ``/api/platform/orgs/{org_id}/users/{user_id}``):
  the org in the path scopes the user. Org B's account on org A's path is a
  404 "User not found" exactly like an unknown id, whatever the account's kind
  (never a 409 that would tell its state), the id isn't echoed, and nothing
  changes: no row, session, reset token, invitation, email or audit row. The
  same request on org B's path succeeds. Org A's users list and metadata hold
  org A's accounts and seats only.

Completeness: every test registers the routes it covers with ``@covers``. A
test asserts the covered set equals every ``ROUTES`` row whose isolation isn't
"none", so a later issue that adds a tenant route must add its case here.
Platform rows are isolation "none", so the GH-167 cases are tied to the
registered ``/api/platform/orgs/{org_id}/users/{user_id}/...`` routes instead.

Inputs: the FakeDb world (chats and chat messages in its tables), the server's
chat runtime (pending confirmations), a stub agent (``agent.run`` is an
AsyncMock), fake OAuth client credentials and a fresh Fernet key per test.
Outputs: pass/fail only.

Security notes: every id, email, password and token is a fixed fake value or
generated per test. No test reaches Google or Microsoft: token revocation is
patched, and the consent URL is only built, never fetched.
"""

from __future__ import annotations

import copy
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, cast
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi.routing import APIRoute

from admino import oauth, org_permissions, server
from admino.oauth import encrypt_refresh_token
from tests.db_fakes import ORG_NAME, FakeDb
from tests.tenancy_world import (
    ATTACHMENT_NOT_FOUND,
    CHAT_NOT_FOUND,
    PASSWORD,
    ROUTES,
    UPLOAD_BODY,
    Account,
    World,
    attachment_files,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_attachment,
    seed_chat,
    seed_failed_chat,
    seed_pending_confirmation,
    seed_trashed_attachment,
    seed_trashed_chat,
    stub_agent,
    upload_headers,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import MemberRole

Route = tuple[str, str]

_SHARED_CHAT: Final = "shared-163"
_A_INVITEE: Final = "a-invitee-163@example.ch"
_B_INVITEE: Final = "b-invitee-163@example.ch"
_A_DEACTIVATED: Final = "a-deactivated-164@example.ch"
_B_DEACTIVATED: Final = "b-deactivated-164@example.ch"
_B_INVITED: Final = "b-invited-164@example.ch"
_USER_NOT_FOUND: Final = {"detail": "User not found"}
# One PATCH that changes every field the body allows on an Org Admin: role (a demotion,
# through the last-admin guard, GH-306), name and email.
_USER_PATCH: Final = {"role": "editor", "name": "Umbenannt 164", "email": "renamed-164@example.ch"}
_PROVIDERS: Final = ("google", "microsoft")
_LABELS: Final = {"google": "Google", "microsoft": "Microsoft"}

# ---------------------------------------------------------------------------
# Coverage registry: which tests are the cross-org cases of which route
# ---------------------------------------------------------------------------

_COVERED: dict[Route, list[str]] = {}


def covers[F: Callable[..., object]](*routes: Route) -> Callable[[F], F]:
    """Register the decorated test as a cross-org case of each ``(method, path)``."""

    def register(test: F) -> F:
        name = str(getattr(test, "__name__", test))
        for route in routes:
            _COVERED.setdefault(route, []).append(name)
        return test

    return register


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (residency off) with their members and a Super Admin, in a FakeDb.

    GH-187: attachments live under ``tmp_path``; both orgs have a storage quota.
    """
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def agent() -> MagicMock:
    """The stub agent: ``agent.run`` is an AsyncMock answering a final result."""
    return stub_agent()


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app, built after the world (create_app clears the in-memory state)."""
    return make_client(make_app(agent))


@pytest.fixture()
def revoke(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    """OAuth env vars (fresh Fernet key, fake client credentials) and patched revocations."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "fake-google-client-163.apps.example")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "fake-google-client-secret-163")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "fake-microsoft-client-163")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "fake-microsoft-client-secret-163")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "https://admino.example.ch/api/oauth/callback")
    mocks = {"google": AsyncMock(return_value=None), "microsoft": AsyncMock(return_value=None)}
    monkeypatch.setattr("admino.oauth._revoke_google_token", mocks["google"])
    monkeypatch.setattr("admino.oauth._revoke_microsoft_token", mocks["microsoft"])
    return mocks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _plain(value: Any) -> uuid.UUID:
    """A plain uuid.UUID from a stored id (plain or asyncpg UUID)."""
    return uuid.UUID(str(value))


def _state(db: FakeDb) -> dict[str, Any]:
    """Everything a refused cross-org request must leave as it was.

    Every table (``chats``, ``chat_messages`` and ``attachments`` included), the
    sessions as token hash -> (user, session id) (any request may refresh the
    caller's ``last_seen_at``), plus the chat runtime (its entries and every
    stored chat's pending confirmation), OAuth states, pending critical
    promotions and (GH-187) every file under the attachments root.
    """
    tables = db.snapshot()
    sessions = tables.pop("sessions")
    tables["sessions"] = {
        token_hash: (str(row["user_id"]), str(row["session_id"]))
        for token_hash, row in sessions.items()
    }
    tables["chat_runtime"] = chat_runtime_state(db)
    tables["oauth_states"] = dict(server._oauth_pending_states)
    tables["promotions"] = dict(org_permissions._pending)
    tables["attachment_files"] = attachment_files()
    return tables


def _invite(client: TestClient, admin: Account, email: str) -> str:
    """Invite ``email`` as an Editor into the admin's org over HTTP; the invitation id."""
    response = client.post(
        "/api/org/invitations", json={"email": email, "role": "editor"}, headers=admin.cookie
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _seed_pending(
    world: World, account: Account, session_id: str, confirmation_id: str
) -> uuid.UUID:
    """The account's legacy chat of ``session_id`` (persisted, GH-176) with a live pending
    confirmation in the chat runtime; the chat's id."""
    chat_id = seed_chat(world.db, account, legacy_session_id=session_id)
    seed_pending_confirmation(account, chat_id, confirmation_id)
    return chat_id


def _confirm(
    client: TestClient, caller: Account, confirmation_id: str, session_id: str
) -> httpx.Response:
    """Approve ``confirmation_id`` of the legacy chat ``session_id`` as ``caller``."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        json={"session_id": session_id, "confirmation_id": confirmation_id, "approved": True},
        headers=caller.cookie,
    )


def _run_session_id(agent: MagicMock) -> str:
    """The chat id (``session_id``, positional or keyword) the agent's one run got."""
    call = agent.run.await_args
    assert call is not None
    return str(call.kwargs["session_id"] if "session_id" in call.kwargs else call.args[1])


def _matrix(response: httpx.Response) -> dict[tuple[str, str], str]:
    """A permissions response as (tool, action) -> state."""
    assert response.status_code == 200, response.text
    return {
        (entry["tool"], entry["action"]): entry.get("permission", entry.get("state"))
        for entry in response.json()["permissions"]
    }


def _flat(matrix: dict[str, dict[str, str]]) -> dict[tuple[str, str], str]:
    """A stored matrix (tool -> {action: state}) as (tool, action) -> state."""
    return {
        (tool, action): state
        for tool, actions in matrix.items()
        for action, state in actions.items()
    }


def _critical(client: TestClient, admin: Account) -> dict[tuple[str, str], dict[str, Any]]:
    """GET /api/org/critical-permissions as (tool, action) -> entry."""
    response = client.get("/api/org/critical-permissions", headers=admin.cookie)
    assert response.status_code == 200, response.text
    return {(entry["tool"], entry["action"]): entry for entry in response.json()["permissions"]}


def _user_settings_row(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any] | None:
    """The user's stored user_settings row (a copy), if any."""
    for owner, row in db.user_settings.items():
        if _plain(owner) == user_id:
            return copy.deepcopy(row)
    return None


def _audit_org_ids(rows: list[dict[str, Any]]) -> set[uuid.UUID | None]:
    """The org ids of audit rows."""
    return {None if row["org_id"] is None else _plain(row["org_id"]) for row in rows}


def _org_trash_state(world: World, org_id: uuid.UUID) -> dict[str, Any]:
    """GH-194: one org's chats, chat messages and attachments rows (trashed ones
    included), its files under the attachments root (originals and derived files) and
    its audit rows, as copies."""
    tables = world.db.snapshot()
    return {
        name: sorted(
            (row for row in tables[name].values() if _plain(row["org_id"]) == org_id),
            key=lambda row: str(row["id"]),
        )
        for name in ("chats", "chat_messages", "attachments")
    } | {
        "files": {
            path: data for path, data in attachment_files().items() if path.startswith(f"{org_id}/")
        },
        "audit": [
            copy.deepcopy(row)
            for row in world.db.audit_rows()
            if row["org_id"] is not None and _plain(row["org_id"]) == org_id
        ],
    }


def _switch_off(db: FakeDb, org_id: uuid.UUID, *tools: str) -> None:
    """Switch tool services off in the org's existing org_settings row (build_world made it)."""
    row = db.org_settings[org_id]
    for tool in tools:
        row[f"{tool}_enabled"] = False


# GH-169: org B's own profile, instructions and policies (markers A must never see).
_B_NAME: Final = "Zephyrmarker Beispiel GmbH"
_B_INSTRUCTIONS: Final = "Zephyrmarker: Anweisungen nur fuer Org B."
_B_POLICIES: Final = {
    "session_idle_timeout_minutes": 90,
    "session_max_lifetime_hours": 6,
    "trash_retention_days": 10,
}
# Org A's sections as build_world leaves them (the defaults; platform trash bounds 0..90).
_A_SECTIONS: Final = {
    "profile": {"display_name": ORG_NAME, "default_response_language": "en"},
    "instructions": "",
    "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
    "retention": {"trash_retention_days": 30, "trash_min_days": 0, "trash_max_days": 90},
}
# One change per GH-169 section (and all of them), sent by org A's Org Admin.
_A_SECTION_PATCHES: Final = [
    pytest.param(
        {"profile": {"display_name": "Org A Neu AG", "default_response_language": "de"}},
        id="profile",
    ),
    pytest.param({"instructions": "Org A: antworte formell."}, id="instructions"),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 4}},
        id="security",
    ),
    pytest.param({"retention": {"trash_retention_days": 14}}, id="retention"),
    pytest.param(
        {
            "profile": {"display_name": "Org A Neu AG", "default_response_language": "fr"},
            "instructions": "Org A: antworte formell.",
            "security": {"session_idle_timeout_minutes": 45, "session_max_lifetime_hours": 2},
            "retention": {"trash_retention_days": 7},
        },
        id="every-section",
    ),
]


def _seed_org_b_settings(world: World) -> None:
    """Give org B its own name, language, instructions and policies (build_world made
    its org_settings row)."""
    world.db.add_org(world.org_b, name=_B_NAME, default_response_language="it")
    world.db.org_settings[world.org_b].update(instructions=_B_INSTRUCTIONS, **_B_POLICIES)


def _session_policies(world: World, *, inside: uuid.UUID | None = None) -> dict[bytes, Any]:
    """(idle timeout, created_at, expires_at) of the sessions of org ``inside``'s users, or
    of every user outside org A when ``inside`` is None (org B's and the Super Admin's)."""
    owners = {
        user_id: None if row["org_id"] is None else _plain(row["org_id"])
        for user_id, row in world.db.users.items()
    }
    return {
        token_hash: (row["idle_timeout_minutes"], row["created_at"], row["expires_at"])
        for token_hash, row in world.db.sessions.items()
        if (owners.get(_plain(row["user_id"])) == inside)
        or (inside is None and owners.get(_plain(row["user_id"])) != world.org_a)
    }


def _org_slice(world: World, org_id: uuid.UUID) -> dict[str, Any]:
    """Copies of an org's org_settings row, organizations row and its users' sessions."""
    return copy.deepcopy(
        {
            "org_settings": world.db.org_settings_row(org_id),
            "organization": world.db.orgs[org_id],
            "sessions": _session_policies(world, inside=org_id),
        }
    )


def _member(world: World, label: str) -> Account:
    """The account of a label: ``"super_admin"`` or ``"<a|b>.<role>"``."""
    if label == "super_admin":
        return world.super_admin
    org, role = label.split(".")
    members = world.a if org == "a" else world.b
    return members[cast("MemberRole", role)]


# ---------------------------------------------------------------------------
# 1. path_id routes: another org's id is a 404 like an unknown id, nothing changes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PathIdCase:
    """One path_id route: whom it serves, its 404 and how to seed and request it.

    ``seed_foreign`` stores org B's resource and returns its id; ``seed_own``
    stores org A's. ``send`` requests the route for an id as a caller. The 404
    body is ``{"detail": detail}``, plus ``"reason"`` when the route documents
    one (GH-176's ``chat_not_found``).
    """

    caller: MemberRole
    detail: str
    own_status: int
    seed_foreign: Callable[[World, TestClient], str]
    seed_own: Callable[[World, TestClient], str]
    send: Callable[[TestClient, Account, str], httpx.Response]
    unknown_id: Callable[[], str]
    reason: str | None = None

    @property
    def not_found(self) -> dict[str, str]:
        """The route's documented 404 body."""
        body = {"detail": self.detail}
        if self.reason is not None:
            body["reason"] = self.reason
        return body


def _uuid_id() -> str:
    return str(uuid.uuid4())


def _chat_id() -> str:
    return f"unknown-{uuid.uuid4().hex}"


def _b_session(world: World, _client: TestClient) -> str:
    return str(world.db.session_id_of(world.b["editor"].token))


def _a_second_session(world: World, _client: TestClient) -> str:
    return str(world.db.session_id_of(world.db.open_session(world.a["editor"].user_id)))


def _b_editor_id(world: World, _client: TestClient) -> str:
    return str(world.b["editor"].user_id)


def _a_editor_id(world: World, _client: TestClient) -> str:
    return str(world.a["editor"].user_id)


def _second_org_admin(world: World, org_id: uuid.UUID) -> str:
    """A second active Org Admin of the org (the world's stays), with a live session; its id."""
    user_id = world.db.add_account(role="org_admin", org_id=org_id)
    world.db.open_session(user_id)
    return str(user_id)


def _b_second_org_admin(world: World, _client: TestClient) -> str:
    return _second_org_admin(world, world.org_b)


def _a_second_org_admin(world: World, _client: TestClient) -> str:
    return _second_org_admin(world, world.org_a)


def _deactivated(world: World, org_id: uuid.UUID, email: str) -> str:
    """A deactivated Editor of the org (no session); its id."""
    return str(
        world.db.add_account(role="editor", org_id=org_id, status="deactivated", email=email)
    )


def _b_deactivated(world: World, _client: TestClient) -> str:
    return _deactivated(world, world.org_b, _B_DEACTIVATED)


def _a_deactivated(world: World, _client: TestClient) -> str:
    return _deactivated(world, world.org_a, _A_DEACTIVATED)


def _b_invited(world: World) -> str:
    """An invited account of org B with its pending invitation; the account's id."""
    invited = world.db.add_account(
        role="editor",
        org_id=world.org_b,
        status="invited",
        name=None,
        password_hash=None,
        email=_B_INVITED,
    )
    world.db.add_invitation(invited)
    return str(invited)


def _b_invitation(world: World, client: TestClient) -> str:
    return _invite(client, world.b["org_admin"], _B_INVITEE)


def _a_invitation(world: World, client: TestClient) -> str:
    return _invite(client, world.a["org_admin"], _A_INVITEE)


def _b_pending(world: World, _client: TestClient) -> str:
    """B's editor's pending confirmation; its legacy session id and confirmation id are
    the same."""
    _seed_pending(world, world.b["editor"], "b-pending-163", "b-pending-163")
    return "b-pending-163"


def _a_pending(world: World, _client: TestClient) -> str:
    _seed_pending(world, world.a["editor"], "a-pending-163", "a-pending-163")
    return "a-pending-163"


# GH-176: B's chat carries this marker in its title, messages and confirmation id.
_B_MARKER: Final = "B-secret-176"
_A_MARKER: Final = "A-own-176"


def _marked_chat(world: World, owner: Account, marker: str) -> uuid.UUID:
    """A titled chat of ``owner`` holding a question and an answer, with a live pending
    confirmation (id ``conf-<marker>``) in the chat runtime; all carry ``marker``."""
    chat_id = seed_chat(
        world.db,
        owner,
        title=f"{marker} Vertragsentwurf",
        messages=(("user", f"{marker} question"), ("assistant", f"{marker} answer")),
    )
    seed_pending_confirmation(owner, chat_id, f"conf-{marker}")
    return chat_id


def _b_chat(world: World, _client: TestClient) -> str:
    return str(_marked_chat(world, world.b["editor"], _B_MARKER))


def _a_chat(world: World, _client: TestClient) -> str:
    return str(_marked_chat(world, world.a["editor"], _A_MARKER))


def _get_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.get(f"/api/chats/{ident}", headers=caller.cookie)


def _rename_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.patch(
        f"/api/chats/{ident}", json={"title": "Umbenannt 176"}, headers=caller.cookie
    )


def _trash_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.delete(f"/api/chats/{ident}", headers=caller.cookie)


def _send_chat_message(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(
        f"/api/chats/{ident}/messages",
        json={"message": "Hallo aus Org A 176"},
        headers=caller.cookie,
    )


def _stop_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-8: POST /api/chats/{chat_id}/stop, no body (an idle chat answers stopped false)."""
    return client.post(f"/api/chats/{ident}/stop", headers=caller.cookie)


def _retry_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-245: POST /api/chats/{chat_id}/retry, no body (re-run the failed last turn)."""
    return client.post(f"/api/chats/{ident}/retry", headers=caller.cookie)


# GH-245: a chat whose one turn failed carries the marker in its title and messages.
def _failed_marked_chat(world: World, owner: Account, marker: str) -> uuid.UUID:
    """A titled chat of ``owner`` whose one turn failed (the question, then the answer
    stored ``error``), all carrying ``marker``: its owner's retry re-runs it."""
    return seed_failed_chat(
        world.db,
        owner,
        title=f"{marker} Vertragsentwurf",
        question=f"{marker} question",
        answer=f"{marker} failed answer",
    )


def _b_failed_chat(world: World, _client: TestClient) -> str:
    return str(_failed_marked_chat(world, world.b["editor"], _B_MARKER))


def _a_failed_chat(world: World, _client: TestClient) -> str:
    return str(_failed_marked_chat(world, world.a["editor"], _A_MARKER))


def _upload_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-187: upload a short text file (raw body, name in X-Attachment-Name) into a chat."""
    return client.post(
        f"/api/chats/{ident}/attachments",
        content=UPLOAD_BODY,
        headers={**upload_headers(), **caller.cookie},
    )


# GH-187: the attachment of a marked chat carries the marker in its name and its bytes.
def _marked_attachment(world: World, owner: Account, marker: str) -> uuid.UUID:
    """An attachment named and filled with ``marker``, in a marked chat of ``owner``."""
    chat_id = _marked_chat(world, owner, marker)
    return seed_attachment(
        world.db,
        chat_id,
        filename=f"{marker} Vertrag.txt",
        data=f"{marker} Vertragsinhalt\n".encode(),
    )


def _b_attachment(world: World, _client: TestClient) -> str:
    return str(_marked_attachment(world, world.b["editor"], _B_MARKER))


def _a_attachment(world: World, _client: TestClient) -> str:
    return str(_marked_attachment(world, world.a["editor"], _A_MARKER))


def _get_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.get(f"/api/attachments/{ident}", headers=caller.cookie)


def _download_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.get(f"/api/attachments/{ident}/content", headers=caller.cookie)


def _exclude_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-190: PATCH /api/attachments/{attachment_id} ``{"active": false}``."""
    return client.patch(f"/api/attachments/{ident}", json={"active": False}, headers=caller.cookie)


def _list_chat_attachments(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-190: GET /api/chats/{chat_id}/attachments."""
    return client.get(f"/api/chats/{ident}/attachments", headers=caller.cookie)


def _delete_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-194: DELETE /api/attachments/{attachment_id} (move a live file to the trash)."""
    return client.delete(f"/api/attachments/{ident}", headers=caller.cookie)


# GH-194: trash items carry the marker in their title, messages, file names and bytes.
def _marked_trashed_chat(world: World, owner: Account, marker: str) -> uuid.UUID:
    """A trashed chat of ``owner`` titled and holding a question with ``marker``, and a
    file named and filled with ``marker`` trashed with it (original and derived text)."""
    return seed_trashed_chat(
        world.db,
        owner,
        title=f"{marker} Papierkorb",
        messages=(("user", f"{marker} question"), ("assistant", f"{marker} answer")),
        filenames=(f"{marker} Anhang.txt",),
    )


def _marked_trashed_attachment(world: World, owner: Account, marker: str) -> uuid.UUID:
    """A file named and filled with ``marker`` that ``owner`` deleted on its own from a
    live marked chat (original and derived text on disk)."""
    return seed_trashed_attachment(
        world.db,
        _marked_chat(world, owner, marker),
        filename=f"{marker} Papierkorb.txt",
        data=f"{marker} Papierkorbinhalt\n".encode(),
    )


def _b_trashed_chat(world: World, _client: TestClient) -> str:
    return str(_marked_trashed_chat(world, world.b["editor"], _B_MARKER))


def _a_trashed_chat(world: World, _client: TestClient) -> str:
    return str(_marked_trashed_chat(world, world.a["editor"], _A_MARKER))


def _b_trashed_attachment(world: World, _client: TestClient) -> str:
    return str(_marked_trashed_attachment(world, world.b["editor"], _B_MARKER))


def _a_trashed_attachment(world: World, _client: TestClient) -> str:
    return str(_marked_trashed_attachment(world, world.a["editor"], _A_MARKER))


def _restore_trashed_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-194: POST /api/trash/chats/{chat_id}/restore (no body)."""
    return client.post(f"/api/trash/chats/{ident}/restore", headers=caller.cookie)


def _purge_trashed_chat(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-194: DELETE /api/trash/chats/{chat_id} (delete forever)."""
    return client.delete(f"/api/trash/chats/{ident}", headers=caller.cookie)


def _restore_trashed_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-194: POST /api/trash/attachments/{attachment_id}/restore (no body)."""
    return client.post(f"/api/trash/attachments/{ident}/restore", headers=caller.cookie)


def _purge_trashed_attachment(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    """GH-194: DELETE /api/trash/attachments/{attachment_id} (delete forever)."""
    return client.delete(f"/api/trash/attachments/{ident}", headers=caller.cookie)


def _trashed_chat_case(
    own_status: int, send: Callable[[TestClient, Account, str], httpx.Response]
) -> _PathIdCase:
    """A GH-194 trashed-chat route: org A's Editor, the chat_not_found 404, B's / A's
    marked trashed chat."""
    return _PathIdCase(
        caller="editor",
        detail="Chat not found",
        own_status=own_status,
        seed_foreign=_b_trashed_chat,
        seed_own=_a_trashed_chat,
        send=send,
        unknown_id=_uuid_id,
        reason="chat_not_found",
    )


def _trashed_attachment_case(
    own_status: int, send: Callable[[TestClient, Account, str], httpx.Response]
) -> _PathIdCase:
    """A GH-194 trashed-file route: org A's Editor, the attachment_not_found 404, B's / A's
    marked file trashed on its own."""
    return _PathIdCase(
        caller="editor",
        detail="Attachment not found",
        own_status=own_status,
        seed_foreign=_b_trashed_attachment,
        seed_own=_a_trashed_attachment,
        send=send,
        unknown_id=_uuid_id,
        reason="attachment_not_found",
    )


def _attachment_case(
    send: Callable[[TestClient, Account, str], httpx.Response], own_status: int = 200
) -> _PathIdCase:
    """A GH-187 attachment route: org A's Editor, the attachment_not_found 404, B's / A's
    marked live attachment (its file on disk); ``own_status`` on the own one."""
    return _PathIdCase(
        caller="editor",
        detail="Attachment not found",
        own_status=own_status,
        seed_foreign=_b_attachment,
        seed_own=_a_attachment,
        send=send,
        unknown_id=_uuid_id,
        reason="attachment_not_found",
    )


def _chat_case(
    own_status: int, send: Callable[[TestClient, Account, str], httpx.Response]
) -> _PathIdCase:
    """A GH-176 chat route: org A's Editor, the chat_not_found 404, B's / A's marked chat."""
    return _PathIdCase(
        caller="editor",
        detail="Chat not found",
        own_status=own_status,
        seed_foreign=_b_chat,
        seed_own=_a_chat,
        send=send,
        unknown_id=_uuid_id,
        reason="chat_not_found",
    )


def _delete_session(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.delete(f"/api/me/sessions/{ident}", headers=caller.cookie)


def _force_logout(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(f"/api/org/users/{ident}/logout", headers=caller.cookie)


def _patch_user(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.patch(f"/api/org/users/{ident}", json=dict(_USER_PATCH), headers=caller.cookie)


def _deactivate_user(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(f"/api/org/users/{ident}/deactivate", headers=caller.cookie)


def _reactivate_user(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(f"/api/org/users/{ident}/reactivate", headers=caller.cookie)


def _delete_user(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.delete(f"/api/org/users/{ident}", headers=caller.cookie)


def _reset_user_password(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(f"/api/org/users/{ident}/password-reset", headers=caller.cookie)


def _revoke_invitation(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.delete(f"/api/org/invitations/{ident}", headers=caller.cookie)


def _resend_invitation(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return client.post(f"/api/org/invitations/{ident}/resend", headers=caller.cookie)


def _confirm_same_ids(client: TestClient, caller: Account, ident: str) -> httpx.Response:
    return _confirm(client, caller, ident, ident)


_PATH_ID_CASES: Final[dict[Route, _PathIdCase]] = {
    ("DELETE", "/api/me/sessions/{session_id}"): _PathIdCase(
        caller="editor",
        detail="Session not found",
        own_status=204,
        seed_foreign=_b_session,
        seed_own=_a_second_session,
        send=_delete_session,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/org/users/{user_id}/logout"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=204,
        seed_foreign=_b_editor_id,
        seed_own=_a_editor_id,
        send=_force_logout,
        unknown_id=_uuid_id,
    ),
    # GH-306: the PATCH demotes; its targets are second Org Admins (each org keeps its own).
    ("PATCH", "/api/org/users/{user_id}"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=200,
        seed_foreign=_b_second_org_admin,
        seed_own=_a_second_org_admin,
        send=_patch_user,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/org/users/{user_id}/deactivate"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=200,
        seed_foreign=_b_editor_id,
        seed_own=_a_editor_id,
        send=_deactivate_user,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/org/users/{user_id}/reactivate"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=200,
        seed_foreign=_b_deactivated,
        seed_own=_a_deactivated,
        send=_reactivate_user,
        unknown_id=_uuid_id,
    ),
    ("DELETE", "/api/org/users/{user_id}"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=204,
        seed_foreign=_b_editor_id,
        seed_own=_a_editor_id,
        send=_delete_user,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/org/users/{user_id}/password-reset"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=202,
        seed_foreign=_b_editor_id,
        seed_own=_a_editor_id,
        send=_reset_user_password,
        unknown_id=_uuid_id,
    ),
    ("DELETE", "/api/org/invitations/{invitation_id}"): _PathIdCase(
        caller="org_admin",
        detail="Invitation not found",
        own_status=204,
        seed_foreign=_b_invitation,
        seed_own=_a_invitation,
        send=_revoke_invitation,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/org/invitations/{invitation_id}/resend"): _PathIdCase(
        caller="org_admin",
        detail="Invitation not found",
        own_status=200,
        seed_foreign=_b_invitation,
        seed_own=_a_invitation,
        send=_resend_invitation,
        unknown_id=_uuid_id,
    ),
    ("POST", "/api/confirm/{confirmation_id}"): _PathIdCase(
        caller="editor",
        detail="No pending confirmation for this session",
        own_status=200,
        seed_foreign=_b_pending,
        seed_own=_a_pending,
        send=_confirm_same_ids,
        unknown_id=_chat_id,
    ),
    # GH-176: persisted chats, private to their owner.
    ("GET", "/api/chats/{chat_id}"): _chat_case(200, _get_chat),
    ("PATCH", "/api/chats/{chat_id}"): _chat_case(200, _rename_chat),
    ("DELETE", "/api/chats/{chat_id}"): _chat_case(204, _trash_chat),
    ("POST", "/api/chats/{chat_id}/messages"): _chat_case(200, _send_chat_message),
    # GH-8: stopping the chat's streamed run (none here: own chat answers 200 stopped false).
    ("POST", "/api/chats/{chat_id}/stop"): _chat_case(200, _stop_chat),
    # GH-245: the retry of a failed turn. B's and A's chats are retryable for their owners
    # (the answer failed), so the 404 is the boundary, not a 409; own chat: 200, re-run.
    ("POST", "/api/chats/{chat_id}/retry"): _PathIdCase(
        caller="editor",
        detail="Chat not found",
        own_status=200,
        seed_foreign=_b_failed_chat,
        seed_own=_a_failed_chat,
        send=_retry_chat,
        unknown_id=_uuid_id,
        reason="chat_not_found",
    ),
    # GH-187: only the chat's owner uploads (201 into the own chat); only the owner reads.
    ("POST", "/api/chats/{chat_id}/attachments"): _chat_case(201, _upload_attachment),
    ("GET", "/api/attachments/{attachment_id}"): _attachment_case(_get_attachment),
    ("GET", "/api/attachments/{attachment_id}/content"): _attachment_case(_download_attachment),
    # GH-190: only the owner excludes a file (200 on the own one) or lists a chat's files.
    ("PATCH", "/api/attachments/{attachment_id}"): _attachment_case(_exclude_attachment),
    ("GET", "/api/chats/{chat_id}/attachments"): _chat_case(200, _list_chat_attachments),
    # GH-194: only the owner moves a live file to the trash (204 on the own one), restores
    # (200) or deletes forever (204) a trashed chat or a file trashed on its own.
    ("DELETE", "/api/attachments/{attachment_id}"): _attachment_case(_delete_attachment, 204),
    ("POST", "/api/trash/chats/{chat_id}/restore"): _trashed_chat_case(200, _restore_trashed_chat),
    ("DELETE", "/api/trash/chats/{chat_id}"): _trashed_chat_case(204, _purge_trashed_chat),
    ("POST", "/api/trash/attachments/{attachment_id}/restore"): _trashed_attachment_case(
        200, _restore_trashed_attachment
    ),
    ("DELETE", "/api/trash/attachments/{attachment_id}"): _trashed_attachment_case(
        204, _purge_trashed_attachment
    ),
}

_PATH_ID_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]} {route[1]}") for route in _PATH_ID_CASES
]

# The chat routes of GH-176 (and GH-8's stop route, GH-187's upload, GH-190's list of a
# chat's attachments, GH-245's retry) that name a chat in the path.
_CHAT_ROUTES: Final[tuple[Route, ...]] = (
    ("GET", "/api/chats/{chat_id}"),
    ("PATCH", "/api/chats/{chat_id}"),
    ("DELETE", "/api/chats/{chat_id}"),
    ("POST", "/api/chats/{chat_id}/messages"),
    ("POST", "/api/chats/{chat_id}/stop"),
    ("POST", "/api/chats/{chat_id}/attachments"),
    # GH-190: the list of a chat's attachments.
    ("GET", "/api/chats/{chat_id}/attachments"),
    # GH-245: the retry (on these complete chats it would be a 409 for their owner).
    ("POST", "/api/chats/{chat_id}/retry"),
)
# Space-free ids, so the RED record (gates.sh cuts node ids at a space) names each case.
_CHAT_ROUTE_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]}:{route[1]}") for route in _CHAT_ROUTES
]
# (caller, owner) in org A: chats are private, an Org Admin reads no member's chat.
_COLLEAGUE_PAIRS: Final = [
    pytest.param("editor", "org_admin", id="editor-on-org-admins-chat"),
    pytest.param("org_admin", "editor", id="org-admin-on-editors-chat"),
]

# GH-187: the attachment reads (metadata and download) that name an attachment, and
# GH-190's exclusion.
_ATTACHMENT_ROUTES: Final[tuple[Route, ...]] = (
    ("GET", "/api/attachments/{attachment_id}"),
    ("GET", "/api/attachments/{attachment_id}/content"),
    # GH-190: the exclusion.
    ("PATCH", "/api/attachments/{attachment_id}"),
    # GH-194: moving a live file to the trash.
    ("DELETE", "/api/attachments/{attachment_id}"),
)
_ATTACHMENT_ROUTE_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]}:{route[1]}") for route in _ATTACHMENT_ROUTES
]

# GH-194: restore and delete forever of a trashed chat and of a file trashed on its own.
_TRASH_ITEM_ROUTES: Final[tuple[Route, ...]] = (
    ("POST", "/api/trash/chats/{chat_id}/restore"),
    ("DELETE", "/api/trash/chats/{chat_id}"),
    ("POST", "/api/trash/attachments/{attachment_id}/restore"),
    ("DELETE", "/api/trash/attachments/{attachment_id}"),
)
_TRASH_ITEM_ROUTE_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]}:{route[1]}") for route in _TRASH_ITEM_ROUTES
]

# The org user routes of GH-164 that name a user in the path.
_USER_ROUTES: Final[tuple[Route, ...]] = (
    ("PATCH", "/api/org/users/{user_id}"),
    ("POST", "/api/org/users/{user_id}/deactivate"),
    ("POST", "/api/org/users/{user_id}/reactivate"),
    ("DELETE", "/api/org/users/{user_id}"),
    ("POST", "/api/org/users/{user_id}/password-reset"),
)
_USER_ROUTE_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]} {route[1]}") for route in _USER_ROUTES
]
# Every kind of org B account a user route could be pointed at. B's Org Admin is
# B's only one: a guard that ran before the org check would answer 409 last_admin.
_FOREIGN_KINDS: Final = ("org_admin", "editor", "deactivated", "invited")


def _foreign_account(world: World, kind: str) -> str:
    """Org B's account of ``kind`` (a member role, "deactivated" or "invited"); its id."""
    if kind == "deactivated":
        return _deactivated(world, world.org_b, _B_DEACTIVATED)
    if kind == "invited":
        return _b_invited(world)
    return str(world.b[cast("MemberRole", kind)].user_id)


@pytest.fixture()
def _clean_access_tokens() -> Iterator[None]:
    """An empty process-wide access-token cache before and after the test."""
    oauth.access_tokens.clear()
    yield
    oauth.access_tokens.clear()


class TestPathIdRoutes:
    """Org A's caller with org B's resource ids, for every path_id route."""

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_foreign_id_is_404_with_the_not_found_detail(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """Org B's id answers 404 with the route's documented not-found body."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)

        response = case.send(client, world.a[case.caller], foreign)

        assert (response.status_code, response.json()) == (404, case.not_found)

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_foreign_id_answers_exactly_like_an_unknown_id(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """No existence leak: org B's id and a never-issued id get the same status and body
        (the route's own not-found answer, not a missing route's)."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)
        caller = world.a[case.caller]

        foreign_response = case.send(client, caller, foreign)
        unknown_response = case.send(client, caller, case.unknown_id())

        assert (unknown_response.status_code, unknown_response.json()) == (
            404,
            case.not_found,
        )
        assert (foreign_response.status_code, foreign_response.json()) == (
            unknown_response.status_code,
            unknown_response.json(),
        )
        assert foreign_response.headers.get("content-type") == unknown_response.headers.get(
            "content-type"
        )

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_foreign_id_changes_nothing(
        self, world: World, client: TestClient, agent: MagicMock, route: Route
    ) -> None:
        """No row, audit event, email, session, chat, chat message, runtime confirmation or
        state changes; no run."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)
        before = _state(world.db)

        response = case.send(client, world.a[case.caller], foreign)

        assert (response.status_code, response.json()) == (404, case.not_found)
        assert _state(world.db) == before
        agent.run.assert_not_awaited()

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_error_never_echoes_the_foreign_id(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """The 404 body and headers never repeat org B's id."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)

        response = case.send(client, world.a[case.caller], foreign)

        assert (response.status_code, response.json()) == (404, case.not_found)
        assert foreign not in response.text
        assert all(foreign not in value for value in response.headers.values())

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_own_org_resource_is_reached(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """Control: the same caller reaches its own org's resource (the 404 is the boundary)."""
        case = _PATH_ID_CASES[route]
        own = case.seed_own(world, client)

        response = case.send(client, world.a[case.caller], own)

        assert response.status_code == case.own_status, response.text

    @covers(*_PATH_ID_CASES)
    @pytest.mark.parametrize("route", _PATH_ID_PARAMS)
    def test_cross_org_path_id_owner_org_still_reaches_its_resource_after_the_refusal(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """After org A's 404, org B's caller of the same role still reaches the resource."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)
        assert case.send(client, world.a[case.caller], foreign).status_code == 404

        response = case.send(client, world.b[case.caller], foreign)

        assert response.status_code == case.own_status, response.text


class TestPathIdSideEffects:
    """The named side effects of each path_id refusal, spelled out per route."""

    @covers(("DELETE", "/api/me/sessions/{session_id}"))
    def test_cross_org_session_revoke_keeps_the_other_orgs_session_live(
        self, world: World, client: TestClient
    ) -> None:
        """B's editor's session survives A's attempt; no session.revoke row is written."""
        victim = world.b["editor"]
        session_id = world.db.session_id_of(victim.token)

        response = client.delete(f"/api/me/sessions/{session_id}", headers=world.a["editor"].cookie)

        assert response.status_code == 404
        assert not world.db.session_revoked(victim.token)
        assert world.db.audit_rows("session.revoke") == []
        assert client.get("/api/auth/me", headers=victim.cookie).status_code == 200

    @covers(("POST", "/api/org/users/{user_id}/logout"))
    def test_cross_org_force_logout_keeps_the_other_orgs_users_sessions(
        self, world: World, client: TestClient
    ) -> None:
        """A's Org Admin can't log B's editor out: sessions intact, no force_logout row."""
        victim = world.b["editor"]
        world.db.open_session(victim.user_id)
        sessions_before = {str(row["session_id"]) for row in world.db.sessions_of(victim.user_id)}

        response = client.post(
            f"/api/org/users/{victim.user_id}/logout", headers=world.a["org_admin"].cookie
        )

        assert (response.status_code, response.json()) == (404, {"detail": "User not found"})
        after = {str(row["session_id"]) for row in world.db.sessions_of(victim.user_id)}
        assert after == sessions_before
        assert len(after) == 2
        assert world.db.audit_rows("session.force_logout") == []

    @covers(
        ("DELETE", "/api/org/invitations/{invitation_id}"),
        ("POST", "/api/org/invitations/{invitation_id}/resend"),
    )
    @pytest.mark.parametrize("action", ["revoke", "resend"])
    def test_cross_org_invitation_revoke_or_resend_keeps_the_other_orgs_invitation(
        self, world: World, client: TestClient, action: str
    ) -> None:
        """B's invitation, invited account and link stay; no email queued; no audit row."""
        invitation_id = _invite(client, world.b["org_admin"], _B_INVITEE)
        invited = world.db.user_by_email(_B_INVITEE)
        assert invited is not None
        invited_id = _plain(invited["id"])
        token = world.db.invitation_token(invited_id)
        invitation_before = copy.deepcopy(world.db.invitation_of(invited_id))
        audit_before = len(world.db.audit_rows())
        caller = world.a["org_admin"]

        if action == "revoke":
            response = _revoke_invitation(client, caller, invitation_id)
        else:
            response = _resend_invitation(client, caller, invitation_id)

        assert (response.status_code, response.json()) == (404, {"detail": "Invitation not found"})
        assert world.db.invitation_of(invited_id) == invitation_before
        assert world.db.invitation_by_token(token) is not None
        assert world.db.user_by_email(_B_INVITEE) is not None
        assert len(world.db.invitation_emails(invited_id)) == 1
        assert len(world.db.audit_rows()) == audit_before

    @covers(*_USER_ROUTES)
    @pytest.mark.parametrize("kind", _FOREIGN_KINDS)
    @pytest.mark.parametrize("route", _USER_ROUTE_PARAMS)
    def test_cross_org_user_route_on_any_kind_of_foreign_account_is_404_and_changes_nothing(
        self, world: World, client: TestClient, route: Route, kind: str
    ) -> None:
        """B's last Org Admin, Editor, a deactivated user and an invited account are
        each a 404 "User not found" for A's Org Admin, never a 409 (last_admin,
        invalid_status, seat_limit) that would tell the account's state; nothing changes."""
        sender = _PATH_ID_CASES[route].send
        target = _foreign_account(world, kind)
        before = _state(world.db)

        response = sender(client, world.a["org_admin"], target)

        assert (response.status_code, response.json()) == (404, _USER_NOT_FOUND)
        assert _state(world.db) == before

    @covers(*_USER_ROUTES)
    @pytest.mark.usefixtures("_clean_access_tokens")
    @pytest.mark.parametrize("route", _USER_ROUTE_PARAMS)
    def test_cross_org_user_route_keeps_the_foreign_users_account_sessions_and_data(
        self, world: World, client: TestClient, revoke: dict[str, AsyncMock], route: Route
    ) -> None:
        """B's Editor (a deactivated B user for reactivate) keeps its row (status, role,
        name, email), both sessions, OAuth connections, notes, settings, reset token,
        chat and its messages (GH-176: persisted), the chat's pending confirmation in
        the chat runtime, OAuth state and cached access token; no email is queued, no
        audit row written, nothing revoked at a provider."""
        reactivate = route[1].endswith("/reactivate")
        if reactivate:
            victim = uuid.UUID(_b_deactivated(world, client))
        else:
            victim = world.b["editor"].user_id
            world.db.open_session(victim)  # a second device
        for provider in _PROVIDERS:
            world.db.add_oauth_token(
                victim,
                provider,
                encrypted_refresh_token=encrypt_refresh_token(f"b-{provider}-refresh-164"),
            )
        world.db.add_memory(victim, "client", "B's private note 164")
        world.db.add_user_settings(victim, theme="dark")
        world.db.add_reset_token(victim)
        chat_id = seed_chat(
            world.db,
            victim,
            messages=(("user", "B-secret-164 question"),),
            legacy_session_id=_SHARED_CHAT,
        )
        seed_pending_confirmation(victim, chat_id, "conf-b-164")
        now = datetime.now(UTC)
        server._oauth_pending_states["b-state-164"] = server.OAuthPendingState(
            created_at=time.time(),
            provider="google",
            redirect_uri="https://admino.example.ch/api/oauth/callback",
            user_id=victim,
            session_id=uuid.uuid4(),
        )
        oauth.access_tokens._store(
            (victim, "microsoft"), "b-access-token-164", now + timedelta(minutes=30)
        )
        user_before = copy.deepcopy(world.db.users[victim])
        sessions_before = sorted(str(row["session_id"]) for row in world.db.sessions_of(victim))
        oauth_before = {p: copy.deepcopy(world.db.oauth_token(victim, p)) for p in _PROVIDERS}
        settings_before = _user_settings_row(world.db, victim)
        token_before = copy.deepcopy(world.db.tokens[victim])
        audit_before = copy.deepcopy(world.db.audit_rows())
        outbox_before = copy.deepcopy(world.db.outbox)
        chat_before = (world.db.chat_row(chat_id), world.db.messages_of(chat_id))

        response = _PATH_ID_CASES[route].send(client, world.a["org_admin"], str(victim))

        assert (response.status_code, response.json()) == (404, _USER_NOT_FOUND)
        assert world.db.users[victim] == user_before
        assert sorted(str(row["session_id"]) for row in world.db.sessions_of(victim)) == (
            sessions_before
        )
        assert len(sessions_before) == (0 if reactivate else 2)
        assert {p: world.db.oauth_token(victim, p) for p in _PROVIDERS} == oauth_before
        assert world.db.memories_of(victim) == {"client": "B's private note 164"}
        assert _user_settings_row(world.db, victim) == settings_before
        assert world.db.tokens.get(victim) == token_before
        assert world.db.outbox == outbox_before
        assert world.db.audit_rows() == audit_before
        assert (world.db.chat_row(chat_id), world.db.messages_of(chat_id)) == chat_before
        assert len(chat_before[1]) == 1
        pending = server._chat_runtime.get_pending(chat_id)
        assert pending is not None
        assert pending.confirmation_id == "conf-b-164"
        assert server._oauth_pending_states["b-state-164"].user_id == victim
        assert (victim, "microsoft") in oauth.access_tokens._entries
        assert [mock.await_count for mock in revoke.values()] == [0, 0]

    @covers(("PATCH", "/api/org/users/{user_id}"))
    def test_cross_org_email_change_to_another_orgs_address_never_touches_that_org(
        self, world: World, client: TestClient
    ) -> None:
        """A's Org Admin gives A's Editor the address of B's Editor (other case): 409
        email_taken (uniqueness is platform-wide), B's and A's users are unchanged, no email
        is queued, and the one audit row is org A's, about A's Editor, naming neither B's
        user nor the address; the body echoes neither."""
        victim = world.b["editor"]
        target = world.a["editor"]
        victim_before = copy.deepcopy(world.db.users[victim.user_id])
        target_before = copy.deepcopy(world.db.users[target.user_id])
        outbox_before = copy.deepcopy(world.db.outbox)
        audit_start = len(world.db.audit_rows())

        response = client.patch(
            f"/api/org/users/{target.user_id}",
            json={"email": victim.email.upper()},
            headers=world.a["org_admin"].cookie,
        )

        assert (response.status_code, response.json()) == (
            409,
            {"detail": "A user with this email already exists.", "reason": "email_taken"},
        )
        assert victim.email not in response.text.lower()
        assert str(victim.user_id) not in response.text
        assert world.db.users[victim.user_id] == victim_before
        assert world.db.users[target.user_id] == target_before
        assert world.db.outbox == outbox_before
        new_rows = world.db.audit_rows()[audit_start:]
        assert [
            (row["action"], _plain(row["org_id"]), list(row["target_ids"])) for row in new_rows
        ] == [("user.profile_change", world.org_a, [str(target.user_id)])]
        assert str(victim.user_id) not in repr(new_rows)
        assert victim.email not in repr(new_rows).lower()

    @covers(("POST", "/api/confirm/{confirmation_id}"))
    @pytest.mark.parametrize("reference", ["session_id", "chat_id"])
    def test_cross_org_confirm_with_the_other_orgs_chat_and_confirmation_ids_is_404(
        self, world: World, client: TestClient, agent: MagicMock, reference: str
    ) -> None:
        """B's pending confirmation can't be approved by A's editor, named by B's legacy
        session id or (GH-176) by B's chat id: 404 like a chat without one, still pending,
        no chat created for A, no run."""
        victim = world.b["editor"]
        chat_id = _seed_pending(world, victim, _SHARED_CHAT, "conf-b-163")
        pending = server._chat_runtime.get_pending(chat_id)
        assert pending is not None
        pending_before = pending.model_copy(deep=True)
        before = _state(world.db)
        named = (
            {"session_id": _SHARED_CHAT} if reference == "session_id" else {"chat_id": str(chat_id)}
        )

        response = client.post(
            "/api/confirm/conf-b-163",
            json={**named, "confirmation_id": "conf-b-163", "approved": True},
            headers=world.a["editor"].cookie,
        )

        assert (response.status_code, response.json()) == (
            404,
            {"detail": "No pending confirmation for this session"},
        )
        assert server._chat_runtime.get_pending(chat_id) == pending_before
        assert _state(world.db) == before
        assert world.db.chats_of(world.a["editor"].user_id) == []
        agent.run.assert_not_awaited()

    @covers(("POST", "/api/confirm/{confirmation_id}"))
    def test_cross_org_confirm_in_a_shared_chat_id_never_matches_the_other_orgs_confirmation(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """Both users have a pending in their own legacy chat "shared-163": B's id is
        "Confirmation not found" for A, like an unknown id, and both pendings stay."""
        caller = world.a["editor"]
        a_chat = _seed_pending(world, caller, _SHARED_CHAT, "conf-a-163")
        b_chat = _seed_pending(world, world.b["editor"], _SHARED_CHAT, "conf-b-163")
        before = _state(world.db)

        foreign = _confirm(client, caller, "conf-b-163", _SHARED_CHAT)
        unknown = _confirm(client, caller, "conf-x-163", _SHARED_CHAT)

        assert (foreign.status_code, foreign.json()) == (404, {"detail": "Confirmation not found"})
        assert (unknown.status_code, unknown.json()) == (foreign.status_code, foreign.json())
        assert _state(world.db) == before
        pendings = [server._chat_runtime.get_pending(chat) for chat in (a_chat, b_chat)]
        assert [None if p is None else p.confirmation_id for p in pendings] == [
            "conf-a-163",
            "conf-b-163",
        ]
        agent.run.assert_not_awaited()


class TestChatPathRoutes:
    """GH-176: a chat is its owner's alone; any other caller gets chat_not_found."""

    @covers(*_CHAT_ROUTES)
    @pytest.mark.parametrize("route", _CHAT_ROUTE_PARAMS)
    def test_cross_org_chat_route_keeps_the_other_orgs_chat_messages_and_pending(
        self, world: World, client: TestClient, agent: MagicMock, route: Route
    ) -> None:
        """B's chat keeps its row (title, live, last activity), its messages and its
        pending confirmation in the chat runtime; no chat.delete row, no run; B's title,
        content and confirmation never appear in the 404."""
        chat_id = _marked_chat(world, world.b["editor"], _B_MARKER)
        row_before = world.db.chat_row(chat_id)
        messages_before = world.db.messages_of(chat_id)

        response = _PATH_ID_CASES[route].send(client, world.a["editor"], str(chat_id))

        assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
        assert world.db.chat_row(chat_id) == row_before
        assert world.db.messages_of(chat_id) == messages_before
        assert len(messages_before) == 2
        pending = server._chat_runtime.get_pending(chat_id)
        assert pending is not None
        assert pending.confirmation_id == f"conf-{_B_MARKER}"
        assert world.db.audit_rows("chat.delete") == []
        assert _B_MARKER not in response.text
        agent.run.assert_not_awaited()

    @covers(*_CHAT_ROUTES)
    @pytest.mark.parametrize(("caller_role", "owner_role"), _COLLEAGUE_PAIRS)
    @pytest.mark.parametrize("route", _CHAT_ROUTE_PARAMS)
    def test_cross_org_chat_route_on_a_colleagues_chat_is_404_like_an_unknown_id(
        self,
        world: World,
        client: TestClient,
        agent: MagicMock,
        route: Route,
        caller_role: MemberRole,
        owner_role: MemberRole,
    ) -> None:
        """Another user's chat in the caller's own org (the issue's "another user's chat")
        is the same 404 as an unknown id, for an Org Admin too (owner-private, V1); nothing
        changes, no run, and the owner's title and content never appear."""
        case = _PATH_ID_CASES[route]
        chat_id = _marked_chat(world, world.a[owner_role], "A-colleague-176")
        caller = world.a[caller_role]
        before = _state(world.db)

        colleague = case.send(client, caller, str(chat_id))
        unknown = case.send(client, caller, _uuid_id())

        assert (colleague.status_code, colleague.json()) == (404, CHAT_NOT_FOUND)
        assert (unknown.status_code, unknown.json()) == (404, CHAT_NOT_FOUND)
        assert colleague.headers.get("content-type") == unknown.headers.get("content-type")
        assert _state(world.db) == before
        assert "A-colleague-176" not in colleague.text
        assert str(chat_id) not in colleague.text
        agent.run.assert_not_awaited()


class TestChatRetryPathRoute:
    """GH-245: only the chat's owner retries; another org's or a colleague's failed turn
    is chat_not_found and stays as it was, though its owner could retry it."""

    @covers(("POST", "/api/chats/{chat_id}/retry"))
    @pytest.mark.parametrize("status", ["error", "stopped"])
    def test_cross_org_chat_retry_on_the_other_orgs_failed_turn_is_404_and_keeps_it(
        self, world: World, client: TestClient, agent: MagicMock, status: str
    ) -> None:
        """Org B's chat whose answer ended ``error`` / ``stopped``: org A's Editor gets the
        chat_not_found 404 (no echo of B's title or content); B's chat row and messages
        (the failed status included) stay, no statement calls ``delete_failed_turn`` or
        inserts a message, and the agent never runs. Control: B's Editor then retries it
        (200, one run)."""
        owner = world.b["editor"]
        chat_id = seed_failed_chat(
            world.db,
            owner,
            title=f"{_B_MARKER} Vertragsentwurf",
            question=f"{_B_MARKER} question",
            answer=f"{_B_MARKER} answer",
            status=status,
        )
        row_before = world.db.chat_row(chat_id)
        messages_before = world.db.messages_of(chat_id)
        mark = len(world.db.calls)

        response = _retry_chat(client, world.a["editor"], str(chat_id))
        refused = (
            world.db.chat_row(chat_id),
            world.db.messages_of(chat_id),
            [
                call.normalized
                for call in world.db.calls[mark:]
                if "delete_failed_turn" in call.normalized
                or "insert into chat_messages" in call.normalized
            ],
            agent.run.await_count,
        )
        owners = _retry_chat(client, owner, str(chat_id))

        assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
        assert _B_MARKER not in response.text
        assert refused == (row_before, messages_before, [], 0)
        assert [message["status"] for message in messages_before] == ["complete", status]
        assert owners.status_code == 200, owners.text
        assert agent.run.await_count == 1

    @covers(("POST", "/api/chats/{chat_id}/retry"))
    @pytest.mark.parametrize(("caller_role", "owner_role"), _COLLEAGUE_PAIRS)
    def test_cross_org_chat_retry_on_a_colleagues_failed_turn_is_404_like_an_unknown_id(
        self,
        world: World,
        client: TestClient,
        agent: MagicMock,
        caller_role: MemberRole,
        owner_role: MemberRole,
    ) -> None:
        """A colleague's chat in the caller's own org whose answer failed (an Org Admin's,
        an Editor's; an Org Admin calling too): the same 404 as an unknown
        id, nothing changes (tables, chat runtime, files), no run, and the owner's
        title, content and chat id never appear."""
        chat_id = _failed_marked_chat(world, world.a[owner_role], "A-colleague-245")
        caller = world.a[caller_role]
        before = _state(world.db)

        colleague = _retry_chat(client, caller, str(chat_id))
        unknown = _retry_chat(client, caller, _uuid_id())

        assert (colleague.status_code, colleague.json()) == (404, CHAT_NOT_FOUND)
        assert (unknown.status_code, unknown.json()) == (404, CHAT_NOT_FOUND)
        assert colleague.headers.get("content-type") == unknown.headers.get("content-type")
        assert _state(world.db) == before
        assert "A-colleague-245" not in colleague.text
        assert str(chat_id) not in colleague.text
        agent.run.assert_not_awaited()


class TestAttachmentPathRoutes:
    """GH-187: an attachment is its chat owner's alone; any other caller gets
    attachment_not_found and never sees the file's name or bytes."""

    @covers(*_ATTACHMENT_ROUTES)
    @pytest.mark.parametrize("route", _ATTACHMENT_ROUTE_PARAMS)
    def test_cross_org_attachment_route_keeps_the_other_orgs_file_and_never_shows_it(
        self, world: World, client: TestClient, route: Route
    ) -> None:
        """Org B's attachment, asked for by org A's Org Admin (who manages users but reads
        no member's file): 404 attachment_not_found, no Content-Disposition, B's name and
        bytes in neither the body nor a header; B's row and file stay as they were."""
        attachment_id = _marked_attachment(world, world.b["editor"], _B_MARKER)
        row_before = world.db.attachment_row(attachment_id)
        files_before = attachment_files()

        response = _PATH_ID_CASES[route].send(client, world.a["org_admin"], str(attachment_id))

        assert (response.status_code, response.json()) == (404, ATTACHMENT_NOT_FOUND)
        assert "content-disposition" not in response.headers
        assert _B_MARKER not in response.text
        assert all(_B_MARKER not in value for value in response.headers.values())
        assert world.db.attachment_row(attachment_id) == row_before
        assert attachment_files() == files_before
        assert len(files_before) == 1

    @covers(*_ATTACHMENT_ROUTES)
    @pytest.mark.parametrize(("caller_role", "owner_role"), _COLLEAGUE_PAIRS)
    @pytest.mark.parametrize("route", _ATTACHMENT_ROUTE_PARAMS)
    def test_cross_org_attachment_route_on_a_colleagues_file_is_404_like_an_unknown_id(
        self,
        world: World,
        client: TestClient,
        route: Route,
        caller_role: MemberRole,
        owner_role: MemberRole,
    ) -> None:
        """A colleague's attachment in the caller's own org (an Org Admin's, an Editor's)
        is the same 404 as an unknown id, for an Org Admin too (the chat's owner
        only, V1); nothing changes and the name and bytes never appear."""
        case = _PATH_ID_CASES[route]
        attachment_id = _marked_attachment(world, world.a[owner_role], "A-colleague-187")
        caller = world.a[caller_role]
        before = _state(world.db)

        colleague = case.send(client, caller, str(attachment_id))
        unknown = case.send(client, caller, _uuid_id())

        assert (colleague.status_code, colleague.json()) == (404, ATTACHMENT_NOT_FOUND)
        assert (unknown.status_code, unknown.json()) == (404, ATTACHMENT_NOT_FOUND)
        assert colleague.headers.get("content-type") == unknown.headers.get("content-type")
        assert _state(world.db) == before
        assert "A-colleague-187" not in colleague.text
        assert str(attachment_id) not in colleague.text


class TestTrashPathRoutes:
    """GH-194: org B's trash item, named by org A's Editor: the 404 of an unknown id, and
    every row, file and audit row of org B stays (its derived files included)."""

    @covers(*_TRASH_ITEM_ROUTES)
    @pytest.mark.parametrize("route", _TRASH_ITEM_ROUTE_PARAMS)
    def test_cross_org_trash_route_keeps_the_other_orgs_item_rows_files_and_audit(
        self, world: World, client: TestClient, agent: MagicMock, route: Route
    ) -> None:
        """B's item and the rest of B's trash (rows, messages, files on disk, audit rows)
        are exactly as before; B's marker (title, file name, bytes) never appears in the
        404; no run."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)
        before = _org_trash_state(world, world.org_b)

        response = case.send(client, world.a["editor"], foreign)

        assert (response.status_code, response.json()) == (404, case.not_found)
        assert _org_trash_state(world, world.org_b) == before
        assert len(before["files"]) == 2
        assert _B_MARKER not in response.text
        agent.run.assert_not_awaited()


# ---------------------------------------------------------------------------
# 2. own_org routes: only the caller's organization is read or changed
# ---------------------------------------------------------------------------


class TestOwnOrgRoutes:
    """Org A's callers read and change org A only, while org B is seeded differently."""

    @covers(("GET", "/api/org/settings"))
    def test_cross_org_org_settings_get_reads_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """B switched gmail and onedrive off and has residency on; A's view is A's row."""
        _switch_off(world.db, world.org_b, "gmail", "onedrive")
        world.db.add_org(world.org_b, data_residency=True)

        a_view = client.get("/api/org/settings", headers=world.a["org_admin"].cookie)
        b_view = client.get("/api/org/settings", headers=world.b["org_admin"].cookie)

        assert a_view.status_code == 200, a_view.text
        assert a_view.json()["tools"]["gmail"] is True
        assert a_view.json()["tools"]["onedrive"] is True
        assert a_view.json()["data_residency"] is False
        assert b_view.json()["tools"]["gmail"] is False  # control: B's seed is visible to B
        assert b_view.json()["data_residency"] is True

    @covers(("PATCH", "/api/org/settings"))
    def test_cross_org_org_settings_patch_changes_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """A switching outlook off changes A's row only; the audit event names org A."""
        _switch_off(world.db, world.org_b, "gmail")
        b_before = world.db.org_tools(world.org_b)

        response = client.patch(
            "/api/org/settings",
            json={"tools": {"outlook": False}},
            headers=world.a["org_admin"].cookie,
        )

        assert response.status_code == 200, response.text
        a_after = world.db.org_tools(world.org_a)
        assert a_after is not None
        assert a_after["outlook"] is False
        assert a_after["gmail"] is True
        assert world.db.org_tools(world.org_b) == b_before
        rows = world.db.audit_rows("org.settings_change")
        assert rows
        assert _audit_org_ids(rows) == {world.org_a}

    @covers(("GET", "/api/org/settings"))
    @pytest.mark.parametrize("org_b_in_query", [False, True], ids=["plain", "org-b-id-in-query"])
    def test_cross_org_org_settings_get_never_shows_the_other_orgs_profile_or_policies(
        self, world: World, client: TestClient, org_b_in_query: bool
    ) -> None:
        """GH-169: B has its own name, language, instructions and policies; A's admin reads
        A's own (the defaults), even with B's id in the query; B's admin reads B's."""
        _seed_org_b_settings(world)
        query = {"org_id": str(world.org_b)} if org_b_in_query else None

        a_view = client.get("/api/org/settings", headers=world.a["org_admin"].cookie, params=query)
        b_view = client.get("/api/org/settings", headers=world.b["org_admin"].cookie)

        assert a_view.status_code == 200, a_view.text
        body = a_view.json()
        assert {section: body.get(section) for section in _A_SECTIONS} == _A_SECTIONS
        assert "zephyrmarker" not in a_view.text.lower()
        b_body = b_view.json()
        assert (b_body["profile"]["display_name"], b_body["instructions"]) == (
            _B_NAME,
            _B_INSTRUCTIONS,
        )  # control: B's seed is visible to B

    @covers(("PATCH", "/api/org/settings"))
    @pytest.mark.parametrize("body", _A_SECTION_PATCHES)
    def test_cross_org_org_settings_section_patch_changes_only_the_callers_org(
        self, world: World, client: TestClient, body: dict[str, Any]
    ) -> None:
        """GH-169: A's change reaches A (control) and leaves B's org_settings row,
        organizations row and sessions, and the Super Admin's sessions, as they were;
        every audit event names org A."""
        _seed_org_b_settings(world)
        a_before = _org_slice(world, world.org_a)
        b_before = _org_slice(world, world.org_b)
        outside_before = _session_policies(world)

        response = client.patch("/api/org/settings", json=body, headers=world.a["org_admin"].cookie)

        assert response.status_code == 200, response.text
        assert _org_slice(world, world.org_a) != a_before
        assert _org_slice(world, world.org_b) == b_before
        assert _session_policies(world) == outside_before
        rows = world.db.audit_rows("org.settings_change")
        assert rows
        assert _audit_org_ids(rows) == {world.org_a}
        assert {tuple(row["target_ids"]) for row in rows} == {(str(world.org_a),)}

    @covers(("GET", "/api/org/permissions"))
    def test_cross_org_permission_matrix_get_reads_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """B's changed rows never show up in A's matrix; A sees exactly its stored rows."""
        world.db.add_permissions(
            world.org_b, {"google_calendar": {"create": "deny"}, "google_drive": {"read": "deny"}}
        )

        a_matrix = _matrix(client.get("/api/org/permissions", headers=world.a["org_admin"].cookie))
        b_matrix = _matrix(client.get("/api/org/permissions", headers=world.b["org_admin"].cookie))

        assert a_matrix == _flat(world.db.org_permissions(world.org_a))
        assert a_matrix[("google_calendar", "create")] == "confirm"
        assert a_matrix[("google_drive", "read")] == "allow"
        assert b_matrix[("google_calendar", "create")] == "deny"  # control
        assert b_matrix[("google_drive", "read")] == "deny"

    @covers(("PATCH", "/api/org/permissions"))
    def test_cross_org_permission_matrix_patch_changes_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """A's change lands in A's matrix; B's stored matrix is untouched; the audit names A."""
        world.db.add_permissions(world.org_b, {"google_calendar": {"create": "deny"}})
        b_before = world.db.org_permissions(world.org_b)

        response = client.patch(
            "/api/org/permissions",
            json={"tool": "google_drive", "action": "read", "permission": "deny"},
            headers=world.a["org_admin"].cookie,
        )

        assert response.status_code == 200, response.text
        assert world.db.org_permissions(world.org_a)["google_drive"]["read"] == "deny"
        assert b_before["google_drive"]["read"] == "allow"
        assert world.db.org_permissions(world.org_b) == b_before
        assert _matrix(response) == _flat(world.db.org_permissions(world.org_a))
        rows = world.db.audit_rows("org.permission_change")
        assert rows
        assert _audit_org_ids(rows) == {world.org_a}

    @covers(("GET", "/api/org/critical-permissions"))
    def test_cross_org_critical_permissions_get_reads_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """B promoted gmail.send and has outlook.send pending; A sees neither."""
        world.db.add_permissions(world.org_b, {"gmail": {"send": "confirm"}})
        b_admin = world.b["org_admin"]
        promote = client.patch(
            "/api/org/critical-permissions/outlook/send",
            json={"password": PASSWORD},
            headers=b_admin.cookie,
        )
        assert promote.status_code == 200, promote.text

        a_view = _critical(client, world.a["org_admin"])
        b_view = _critical(client, b_admin)

        assert a_view[("gmail", "send")]["state"] == "deny"
        assert a_view[("outlook", "send")]["pending_at"] is None
        assert all(entry["pending_at"] is None for entry in a_view.values())
        assert b_view[("gmail", "send")]["state"] == "confirm"  # control
        assert b_view[("outlook", "send")]["pending_at"] is not None

    @covers(("PATCH", "/api/org/critical-permissions/{tool}/{action}"))
    def test_cross_org_critical_promote_starts_a_pending_in_the_callers_org_only(
        self, world: World, client: TestClient
    ) -> None:
        """B has gmail.send promoted. A's PATCH is a promotion request in A (pending, 'deny'),
        never a demotion of B's row; B's state and pendings stay."""
        world.db.add_permissions(world.org_b, {"gmail": {"send": "confirm"}})
        b_admin = world.b["org_admin"]
        b_before = _critical(client, b_admin)

        response = client.patch(
            "/api/org/critical-permissions/gmail/send",
            json={"password": PASSWORD},
            headers=world.a["org_admin"].cookie,
        )

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "deny"
        assert response.json()["pending_at"] is not None
        assert world.db.org_permissions(world.org_b)["gmail"]["send"] == "confirm"
        assert world.db.org_permissions(world.org_a)["gmail"]["send"] == "deny"
        assert _critical(client, b_admin) == b_before
        assert {org for org, _tool, _action in org_permissions._pending} == {world.org_a}
        assert world.db.audit_rows("org.permission_demote") == []
        assert _audit_org_ids(world.db.audit_rows("org.permission_promote")) == {world.org_a}

    @covers(("DELETE", "/api/org/critical-permissions/{tool}/{action}/pending"))
    def test_cross_org_critical_cancel_never_cancels_the_other_orgs_pending(
        self, world: World, client: TestClient
    ) -> None:
        """Only B has gmail.send pending: A's cancel is a 404 like a pair nobody has pending,
        B's pending stays, and nothing is written."""
        b_admin = world.b["org_admin"]
        promote = client.patch(
            "/api/org/critical-permissions/gmail/send",
            json={"password": PASSWORD},
            headers=b_admin.cookie,
        )
        assert promote.status_code == 200, promote.text
        b_before = _critical(client, b_admin)
        before = _state(world.db)
        caller = world.a["org_admin"]

        foreign = client.delete(
            "/api/org/critical-permissions/gmail/send/pending", headers=caller.cookie
        )
        nobody = client.delete(
            "/api/org/critical-permissions/outlook/send/pending", headers=caller.cookie
        )

        assert (foreign.status_code, foreign.json()) == (
            404,
            {"detail": "No pending promotion for this permission"},
        )
        assert (nobody.status_code, nobody.json()) == (foreign.status_code, foreign.json())
        assert _state(world.db) == before
        assert world.db.audit_rows("org.permission_promote_cancel") == []
        assert _critical(client, b_admin) == b_before
        assert b_before[("gmail", "send")]["pending_at"] is not None

    @covers(("GET", "/api/permissions/summary"))
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_cross_org_permissions_summary_reflects_only_the_callers_org(
        self, world: World, client: TestClient, role: MemberRole
    ) -> None:
        """B switched gmail off and denies calendar create; A's summary shows A's states."""
        _switch_off(world.db, world.org_b, "gmail")
        world.db.add_permissions(world.org_b, {"google_calendar": {"create": "deny"}})

        a_summary = _matrix(client.get("/api/permissions/summary", headers=world.a[role].cookie))
        b_summary = _matrix(client.get("/api/permissions/summary", headers=world.b[role].cookie))

        assert a_summary[("gmail", "read")] == "allow"
        assert a_summary[("google_calendar", "create")] == "confirm"
        assert set(a_summary) == set(_flat(world.db.org_permissions(world.org_a)))
        assert b_summary[("gmail", "read")] == "disabled"  # control
        assert b_summary[("google_calendar", "create")] == "deny"

    @covers(("GET", "/api/org/invitations"))
    def test_cross_org_invitation_list_shows_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """Both orgs have a pending invitation; A's list has A's only, B's email absent."""
        a_id = _invite(client, world.a["org_admin"], _A_INVITEE)
        b_id = _invite(client, world.b["org_admin"], _B_INVITEE)

        response = client.get("/api/org/invitations", headers=world.a["org_admin"].cookie)

        assert response.status_code == 200, response.text
        listed = response.json()["invitations"]
        assert [(entry["id"], entry["email"]) for entry in listed] == [(a_id, _A_INVITEE)]
        assert _B_INVITEE not in response.text
        assert b_id not in response.text

    @covers(("POST", "/api/org/invitations"))
    def test_cross_org_invitation_create_lands_in_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """A's invited account is a member of org A, audited for A, and absent from B's list."""
        invitation_id = _invite(client, world.a["org_admin"], _A_INVITEE)

        invited = world.db.user_by_email(_A_INVITEE)
        b_list = client.get("/api/org/invitations", headers=world.b["org_admin"].cookie)

        assert invited is not None
        assert _plain(invited["org_id"]) == world.org_a
        assert _audit_org_ids(world.db.audit_rows("invitation.create")) == {world.org_a}
        assert b_list.status_code == 200, b_list.text
        assert b_list.json()["invitations"] == []
        assert invitation_id not in b_list.text

    @covers(("GET", "/api/org/users"))
    def test_cross_org_org_user_list_shows_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """Each org also has a deactivated user, and B an invited one: A's Org Admin lists
        exactly A's active and deactivated users, B's exactly B's; no id or email of the
        other org, and none of the Super Admin, appears in either list."""
        a_off = _a_deactivated(world, client)
        b_off = _b_deactivated(world, client)
        b_invited = _b_invited(world)

        a_view = client.get("/api/org/users", headers=world.a["org_admin"].cookie)
        b_view = client.get("/api/org/users", headers=world.b["org_admin"].cookie)

        assert a_view.status_code == 200, a_view.text
        assert b_view.status_code == 200, b_view.text
        a_ids = {str(account.user_id) for account in world.a.values()} | {a_off}
        b_ids = {str(account.user_id) for account in world.b.values()} | {b_off}
        assert {entry["id"] for entry in a_view.json()["users"]} == a_ids
        assert {entry["id"] for entry in b_view.json()["users"]} == b_ids
        a_marks = [*a_ids, _A_DEACTIVATED, *(account.email for account in world.a.values())]
        b_marks = [
            *b_ids,
            b_invited,
            _B_DEACTIVATED,
            _B_INVITED,
            *(account.email for account in world.b.values()),
        ]
        operator = [str(world.super_admin.user_id), world.super_admin.email]
        assert [mark for mark in [*b_marks, *operator] if mark in a_view.text] == []
        assert [mark for mark in [*a_marks, *operator] if mark in b_view.text] == []

    @covers(("GET", "/api/org/users"))
    def test_cross_org_org_user_seats_count_only_the_callers_org(
        self, world: World, client: TestClient
    ) -> None:
        """GH-165: org A (12 seats) and org B (40 seats) each hold their two members.
        A invites one user; B invites one, has a pending and an expired invited account, a
        deactivated user and three more Editors. A's seats are {"used": 3, "limit": 12}
        (B's active and invited users never count, A's own limit), B's {"used": 8,
        "limit": 40}; neither is shifted by the other org or by the Super Admin."""
        world.db.add_org(world.org_a, seats=12)
        world.db.add_org(world.org_b, seats=40)
        _invite(client, world.a["org_admin"], _A_INVITEE)
        _invite(client, world.b["org_admin"], _B_INVITEE)
        _b_invited(world)
        expired = world.db.add_account(
            role="editor", org_id=world.org_b, status="invited", name=None, password_hash=None
        )
        world.db.add_invitation(expired, sent_ago=timedelta(days=10))
        _b_deactivated(world, client)
        for _ in range(3):
            world.db.add_account(role="editor", org_id=world.org_b)

        a_view = client.get("/api/org/users", headers=world.a["org_admin"].cookie)
        b_view = client.get("/api/org/users", headers=world.b["org_admin"].cookie)

        assert a_view.status_code == 200, a_view.text
        assert b_view.status_code == 200, b_view.text
        assert a_view.json().get("seats") == {"used": 3, "limit": 12}
        assert b_view.json().get("seats") == {"used": 8, "limit": 40}


# ---------------------------------------------------------------------------
# 3. own_user routes: only the caller's own data
# ---------------------------------------------------------------------------

_EVERYONE: Final = (
    "super_admin",
    "a.org_admin",
    "a.editor",
    "b.org_admin",
    "b.editor",
)


class TestOwnUserAccountRoutes:
    """The account routes: me, logout, sessions and settings."""

    @covers(("GET", "/api/auth/me"))
    @pytest.mark.parametrize("label", _EVERYONE)
    def test_cross_org_me_returns_the_callers_own_ids(
        self, world: World, client: TestClient, label: str
    ) -> None:
        """Every account's /api/auth/me is its own: user id, org id and role."""
        account = _member(world, label)

        response = client.get("/api/auth/me", headers=account.cookie)

        assert response.status_code == 200, response.text
        body = response.json()
        expected_org = None if account.org_id is None else str(account.org_id)
        expected_role = None if account.role == "super_admin" else account.role
        assert (body["user_id"], body["org_id"], body["role"]) == (
            str(account.user_id),
            expected_org,
            expected_role,
        )

    @covers(("POST", "/api/auth/logout"))
    def test_cross_org_logout_ends_only_the_callers_session(
        self, world: World, client: TestClient
    ) -> None:
        """A's editor logs out: that one session ends; every other account stays logged in."""
        caller = world.a["editor"]

        response = client.post("/api/auth/logout", headers=caller.cookie)

        assert response.status_code == 204, response.text
        assert world.db.session_revoked(caller.token)
        others = [account for account in world.everyone() if account != caller]
        assert [world.db.session_revoked(account.token) for account in others] == [False] * 4
        assert client.get("/api/auth/me", headers=world.b["editor"].cookie).status_code == 200

    @covers(("GET", "/api/me/sessions"))
    def test_cross_org_my_sessions_lists_only_the_callers_sessions(
        self, world: World, client: TestClient
    ) -> None:
        """A's editor (2 sessions) sees exactly its own; no session id of org B appears."""
        caller = world.a["editor"]
        world.db.open_session(caller.user_id)
        world.db.open_session(world.b["editor"].user_id)

        response = client.get("/api/me/sessions", headers=caller.cookie)

        assert response.status_code == 200, response.text
        listed = {entry["id"] for entry in response.json()["sessions"]}
        own = {str(row["session_id"]) for row in world.db.sessions_of(caller.user_id)}
        others = {
            str(row["session_id"])
            for row in world.db.sessions.values()
            if _plain(row["user_id"]) != caller.user_id
        }
        assert listed == own
        assert len(own) == 2
        assert not listed & others
        assert not any(sid in response.text for sid in others)

    @covers(("GET", "/api/me/settings"))
    def test_cross_org_my_settings_get_reads_only_the_callers_row(
        self, world: World, client: TestClient
    ) -> None:
        """B's editor stored dark/no notifications; A's editor (no row) gets the defaults."""
        world.db.add_user_settings(
            world.b["editor"].user_id, theme="dark", notifications_enabled=False
        )

        a_view = client.get("/api/me/settings", headers=world.a["editor"].cookie)
        b_view = client.get("/api/me/settings", headers=world.b["editor"].cookie)

        assert a_view.status_code == 200, a_view.text
        assert a_view.json()["appearance"]["theme"] == "light"
        assert a_view.json()["notifications"]["enabled"] is True
        assert b_view.json()["appearance"]["theme"] == "dark"  # control

    @covers(("PATCH", "/api/me/settings"))
    def test_cross_org_my_settings_patch_changes_only_the_callers_row(
        self, world: World, client: TestClient
    ) -> None:
        """A's editor switches to system: A's row changes, B's row is untouched."""
        victim = world.b["editor"]
        world.db.add_user_settings(victim.user_id, theme="dark")
        b_before = _user_settings_row(world.db, victim.user_id)
        caller = world.a["editor"]

        response = client.patch(
            "/api/me/settings", json={"appearance": {"theme": "system"}}, headers=caller.cookie
        )

        assert response.status_code == 200, response.text
        a_row = _user_settings_row(world.db, caller.user_id)
        assert a_row is not None
        assert a_row["theme"] == "system"
        assert _user_settings_row(world.db, victim.user_id) == b_before

    @covers(("POST", "/api/me/settings/reset"))
    def test_cross_org_my_settings_reset_changes_only_the_callers_row(
        self, world: World, client: TestClient
    ) -> None:
        """A's editor resets: A is back to the defaults, B's dark theme stays."""
        victim = world.b["editor"]
        caller = world.a["editor"]
        world.db.add_user_settings(victim.user_id, theme="dark", notifications_task_done=True)
        world.db.add_user_settings(caller.user_id, theme="dark", notifications_task_done=True)
        b_before = _user_settings_row(world.db, victim.user_id)

        response = client.post("/api/me/settings/reset", headers=caller.cookie)

        assert response.status_code == 200, response.text
        assert response.json()["appearance"]["theme"] == "light"
        assert _user_settings_row(world.db, victim.user_id) == b_before
        b_view = client.get("/api/me/settings", headers=victim.cookie)
        assert b_view.json()["appearance"]["theme"] == "dark"

    @covers(("GET", "/api/me"))
    def test_cross_org_my_account_get_reads_only_the_callers_row(
        self, world: World, client: TestClient
    ) -> None:
        """GH-166: B's editor has a name, timezone and instructions of its own; A's
        editor sees only its own account, and none of B's values."""
        victim = world.b["editor"]
        world.db.users[victim.user_id].update(
            name="B Editor Quasar",
            timezone="Asia/Tokyo",
            personal_instructions="B-secret-166 instructions",
        )
        caller = world.a["editor"]

        a_view = client.get("/api/me", headers=caller.cookie)
        b_view = client.get("/api/me", headers=victim.cookie)

        assert a_view.status_code == 200, a_view.text
        assert a_view.json()["email"] == caller.email
        for marker in (victim.email, "Quasar", "Asia/Tokyo", "B-secret-166"):
            assert marker not in a_view.text
        assert b_view.json()["personal_instructions"] == "B-secret-166 instructions"  # control

    @covers(("PATCH", "/api/me"))
    def test_cross_org_my_account_patch_changes_only_the_callers_row(
        self, world: World, client: TestClient
    ) -> None:
        """GH-166: A's editor changes its profile; every other account's row (B's
        included) is exactly as it was."""
        caller = world.a["editor"]
        others = {
            account.user_id: copy.deepcopy(world.db.users[account.user_id])
            for account in world.everyone()
            if account != caller
        }

        response = client.patch(
            "/api/me",
            json={
                "name": "A Editor Renamed",
                "response_language": "it",
                "timezone": "Europe/Paris",
                "personal_instructions": "A's own instructions.",
            },
            headers=caller.cookie,
        )

        assert response.status_code == 200, response.text
        assert world.db.users[caller.user_id]["timezone"] == "Europe/Paris"
        assert {user_id: world.db.users[user_id] for user_id in others} == others

    @covers(("POST", "/api/me/password"))
    def test_cross_org_my_password_change_ends_only_the_callers_sessions(
        self, world: World, client: TestClient
    ) -> None:
        """GH-166: A's editor changes its password: its own sessions end; every other
        account (B's included) keeps its session and its password; the audit row is
        org A's."""
        caller = world.a["editor"]
        world.db.open_session(caller.user_id)
        others = [account for account in world.everyone() if account != caller]
        hashes = {
            account.user_id: world.db.users[account.user_id]["password_hash"] for account in others
        }

        response = client.post(
            "/api/me/password",
            json={"current_password": PASSWORD, "new_password": "tenancy-Changed-166-meadow"},
            headers=caller.cookie,
        )

        assert response.status_code == 204, response.text
        assert world.db.sessions_of(caller.user_id) == []
        assert [world.db.session_revoked(account.token) for account in others] == [False] * 4
        assert {
            account.user_id: world.db.users[account.user_id]["password_hash"] for account in others
        } == hashes
        assert client.get("/api/auth/me", headers=world.b["editor"].cookie).status_code == 200
        rows = world.db.audit_rows("password.change")
        assert [(_plain(row["org_id"]), row["target_ids"]) for row in rows] == [
            (world.org_a, [str(caller.user_id)])
        ]


class TestOwnUserOAuthRoutes:
    """Per-user connections, and the data residency of the caller's own org."""

    @covers(("GET", "/api/oauth/google/status"), ("GET", "/api/oauth/microsoft/status"))
    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_cross_org_oauth_status_never_reports_the_other_orgs_connection(
        self, world: World, client: TestClient, revoke: dict[str, AsyncMock], provider: str
    ) -> None:
        """B's editor is connected; A's editor isn't: A's status says not connected."""
        world.db.add_oauth_token(
            world.b["editor"].user_id,
            provider,
            encrypted_refresh_token=encrypt_refresh_token("b-refresh-token-163"),
        )

        a_status = client.get(f"/api/oauth/{provider}/status", headers=world.a["editor"].cookie)
        b_status = client.get(f"/api/oauth/{provider}/status", headers=world.b["editor"].cookie)

        assert a_status.status_code == 200, a_status.text
        assert (a_status.json()["connected"], a_status.json()["healthy"]) == (False, False)
        assert (b_status.json()["connected"], b_status.json()["healthy"]) == (True, True)

    @covers(("GET", "/api/oauth/google/status"), ("GET", "/api/oauth/microsoft/status"))
    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_cross_org_oauth_status_reports_the_callers_org_residency_and_switches(
        self, world: World, client: TestClient, revoke: dict[str, AsyncMock], provider: str
    ) -> None:
        """Org A has residency on and its services off; org B neither: each sees its own."""
        world.db.add_org(world.org_a, data_residency=True)
        _switch_off(
            world.db,
            world.org_a,
            "gmail",
            "google_calendar",
            "google_drive",
            "outlook",
            "outlook_calendar",
            "onedrive",
        )

        a_status = client.get(f"/api/oauth/{provider}/status", headers=world.a["editor"].cookie)
        b_status = client.get(f"/api/oauth/{provider}/status", headers=world.b["editor"].cookie)

        assert a_status.status_code == 200, a_status.text
        assert a_status.json()["data_residency"] is True
        assert {service["enabled"] for service in a_status.json()["services"]} == {False}
        assert b_status.json()["data_residency"] is False
        assert {service["enabled"] for service in b_status.json()["services"]} == {True}

    @covers(("DELETE", "/api/oauth/google"), ("DELETE", "/api/oauth/microsoft"))
    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_cross_org_oauth_disconnect_never_touches_the_other_orgs_connection(
        self, world: World, client: TestClient, revoke: dict[str, AsyncMock], provider: str
    ) -> None:
        """Only B's editor is connected: A's disconnect is 404, B's row stays, nothing revoked."""
        victim = world.b["editor"]
        world.db.add_oauth_token(
            victim.user_id,
            provider,
            encrypted_refresh_token=encrypt_refresh_token("b-refresh-token-163"),
        )
        row_before = copy.deepcopy(world.db.oauth_token(victim.user_id, provider))

        response = client.delete(f"/api/oauth/{provider}", headers=world.a["editor"].cookie)

        assert (response.status_code, response.json()) == (
            404,
            {"detail": f"{_LABELS[provider]} account is not connected."},
        )
        assert world.db.oauth_token(victim.user_id, provider) == row_before
        revoke[provider].assert_not_awaited()
        b_status = client.get(f"/api/oauth/{provider}/status", headers=victim.cookie)
        assert b_status.json()["connected"] is True

    @covers(("DELETE", "/api/oauth/google"), ("DELETE", "/api/oauth/microsoft"))
    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_cross_org_oauth_disconnect_removes_only_the_callers_connection(
        self, world: World, client: TestClient, revoke: dict[str, AsyncMock], provider: str
    ) -> None:
        """Both editors are connected: A's disconnect deletes A's row only."""
        caller = world.a["editor"]
        victim = world.b["editor"]
        for account, secret in ((caller, "a-refresh-token-163"), (victim, "b-refresh-token-163")):
            world.db.add_oauth_token(
                account.user_id, provider, encrypted_refresh_token=encrypt_refresh_token(secret)
            )
        row_before = copy.deepcopy(world.db.oauth_token(victim.user_id, provider))

        response = client.delete(f"/api/oauth/{provider}", headers=caller.cookie)

        assert response.status_code == 200, response.text
        assert world.db.oauth_token(caller.user_id, provider) is None
        assert world.db.oauth_token(victim.user_id, provider) == row_before
        assert revoke[provider].await_count == 1

    @covers(("GET", "/api/oauth/google/authorize"), ("GET", "/api/oauth/microsoft/authorize"))
    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize("resident", ["a", "b"])
    def test_cross_org_oauth_authorize_reads_residency_from_the_callers_org(
        self,
        world: World,
        client: TestClient,
        revoke: dict[str, AsyncMock],
        provider: str,
        resident: str,
    ) -> None:
        """One org has residency on: its editor gets the residency 403, the other org's
        editor gets a consent URL, and the only pending state is bound to that editor."""
        resident_org, open_org = (
            (world.org_a, world.org_b)
            if resident == "a"
            else (
                world.org_b,
                world.org_a,
            )
        )
        world.db.add_org(resident_org, data_residency=True)
        refused_caller = world.a["editor"] if resident == "a" else world.b["editor"]
        allowed_caller = world.b["editor"] if resident == "a" else world.a["editor"]
        assert allowed_caller.org_id == open_org

        refused = client.get(f"/api/oauth/{provider}/authorize", headers=refused_caller.cookie)
        allowed = client.get(f"/api/oauth/{provider}/authorize", headers=allowed_caller.cookie)

        assert (refused.status_code, refused.json()) == (
            403,
            {"detail": server.OAUTH_RESIDENCY_DETAIL},
        )
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["url"].startswith("https://")
        states = list(server._oauth_pending_states.values())
        assert [(state.user_id, state.provider) for state in states] == [
            (allowed_caller.user_id, provider)
        ]


class TestOwnUserChatRoutes:
    """The caller's own chats: the list, creation, and the legacy chat routes, whose
    session id names the caller's own persisted chat (GH-176), never another user's."""

    @covers(("GET", "/api/chats"))
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_cross_org_chat_list_shows_only_the_callers_own_chats(
        self, world: World, client: TestClient, role: MemberRole
    ) -> None:
        """Every member of both orgs owns a chat and the caller two: the caller lists
        exactly its own two; no id or title of a colleague's (the Org Admin reads no
        member's chat) or of org B's appears; B's Editor lists its own (control)."""
        caller = world.a[role]
        own = {
            str(seed_chat(world.db, caller, title=f"Own-176 chat {n}", messages=(("user", "hi"),)))
            for n in (1, 2)
        }
        others: dict[str, str] = {}
        for account in [*world.a.values(), *world.b.values()]:
            if account != caller:
                marker = f"Other-176-{account.email.split('@')[0]}"
                others[str(seed_chat(world.db, account, title=marker))] = marker

        response = client.get("/api/chats", headers=caller.cookie)
        b_view = client.get("/api/chats", headers=world.b["editor"].cookie)

        assert response.status_code == 200, response.text
        assert {entry["id"] for entry in response.json()["chats"]} == own
        assert [mark for pair in others.items() for mark in pair if mark in response.text] == []
        b_own = {str(row["id"]) for row in world.db.chats_of(world.b["editor"].user_id)}
        assert {entry["id"] for entry in b_view.json()["chats"]} == b_own
        assert len(b_own) == 1

    @covers(("POST", "/api/chats"))
    def test_cross_org_chat_create_lands_in_the_callers_org_and_ownership(
        self, world: World, client: TestClient
    ) -> None:
        """The new chat is the caller's, in the caller's org; no other user gets a chat,
        and org B's Editor doesn't list it."""
        caller = world.a["editor"]

        response = client.post("/api/chats", json={"title": "Neu 176"}, headers=caller.cookie)

        assert response.status_code == 201, response.text
        chat_id = uuid.UUID(response.json()["id"])
        row = world.db.chat_row(chat_id)
        assert row is not None
        assert (_plain(row["org_id"]), _plain(row["owner_user_id"])) == (
            world.org_a,
            caller.user_id,
        )
        assert [_plain(key) for key in world.db.chats] == [chat_id]
        b_list = client.get("/api/chats", headers=world.b["editor"].cookie)
        assert b_list.status_code == 200, b_list.text
        assert b_list.json()["chats"] == []

    @covers(("POST", "/api/chats"))
    @pytest.mark.parametrize("field", ["org_id", "owner_user_id"])
    def test_cross_org_chat_create_with_a_smuggled_org_or_owner_is_422_and_creates_nothing(
        self, world: World, client: TestClient, field: str
    ) -> None:
        """Org B's id or B's Editor's id in the body: 422 (unknown field), nothing stored,
        the value not echoed (whose chat it is comes from the session only)."""
        smuggled = str(world.org_b if field == "org_id" else world.b["editor"].user_id)
        before = _state(world.db)

        response = client.post(
            "/api/chats",
            json={"title": "Neu 176", field: smuggled},
            headers=world.a["editor"].cookie,
        )

        assert response.status_code == 422, response.text
        assert smuggled not in response.text
        assert _state(world.db) == before
        assert world.db.chats == {}

    @covers(("POST", "/api/message"))
    def test_cross_org_message_with_the_other_orgs_chat_id_starts_an_empty_chat(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """A's editor sends to B's legacy session id: the run gets A's own new chat (in
        org A, with that legacy session id), no history, A's principal and no external
        content flag from B's chat; B's chat row and messages are unchanged."""
        victim = world.b["editor"]
        victim_chat = seed_chat(
            world.db,
            victim,
            title="B-secret-163 title",
            messages=(("user", "B-secret-163 question"), ("assistant", "B-secret-163 answer")),
            legacy_session_id=_SHARED_CHAT,
            external_content=True,
        )
        victim_before = (world.db.chat_row(victim_chat), world.db.messages_of(victim_chat))
        caller = world.a["editor"]

        response = client.post(
            "/api/message",
            json={"message": "hello", "session_id": _SHARED_CHAT},
            headers=caller.cookie,
        )

        assert response.status_code == 200, response.text
        agent.run.assert_awaited_once()
        kwargs = agent.run.await_args.kwargs
        assert kwargs["history"] == []
        assert (kwargs["principal"].user_id, kwargs["principal"].org_id) == (
            caller.user_id,
            world.org_a,
        )
        assert kwargs.get("earlier_external_content") is False
        own = world.db.chats_of(caller.user_id)
        assert [(row["legacy_session_id"], _plain(row["org_id"])) for row in own] == [
            (_SHARED_CHAT, world.org_a)
        ]
        assert _run_session_id(agent) == str(own[0]["id"])
        assert (response.json()["chat_id"], response.json()["session_id"]) == (
            str(own[0]["id"]),
            _SHARED_CHAT,
        )
        assert (world.db.chat_row(victim_chat), world.db.messages_of(victim_chat)) == (
            victim_before
        )
        assert "B-secret-163" not in response.text
        assert str(victim_chat) not in response.text

    @covers(("POST", "/api/message"))
    def test_cross_org_message_never_cancels_the_other_orgs_pending_confirmation(
        self, world: World, client: TestClient
    ) -> None:
        """A new message in A's legacy chat "shared-163" leaves B's pending in B's chat of
        that session id."""
        victim_chat = _seed_pending(world, world.b["editor"], _SHARED_CHAT, "conf-b-163")

        response = client.post(
            "/api/message",
            json={"message": "hello", "session_id": _SHARED_CHAT},
            headers=world.a["editor"].cookie,
        )

        assert response.status_code == 200, response.text
        pending = server._chat_runtime.get_pending(victim_chat)
        assert pending is not None
        assert pending.confirmation_id == "conf-b-163"


# ---------------------------------------------------------------------------
# 3b. Platform user routes (GH-167): the org in the path scopes the user
# ---------------------------------------------------------------------------


# The Super Admin's user actions, each with its success status on the user's own org.
class TestOwnUserTrashRoutes:
    """GH-194: the caller's own trash only (``own_user``): the list and emptying it."""

    @covers(("GET", "/api/trash"))
    def test_cross_org_trash_list_shows_only_the_callers_own_items(
        self, world: World, client: TestClient
    ) -> None:
        """Org A's and org B's Editors each have a trashed chat and a file trashed on its
        own: A's Editor lists exactly its own two items, never B's ids or marker; B's
        Editor lists its own two (control)."""
        own = {
            str(_marked_trashed_chat(world, world.a["editor"], _A_MARKER)),
            str(_marked_trashed_attachment(world, world.a["editor"], _A_MARKER)),
        }
        foreign = {
            str(_marked_trashed_chat(world, world.b["editor"], _B_MARKER)),
            str(_marked_trashed_attachment(world, world.b["editor"], _B_MARKER)),
        }

        response = client.get("/api/trash", headers=world.a["editor"].cookie)
        b_view = client.get("/api/trash", headers=world.b["editor"].cookie)

        assert response.status_code == 200, response.text
        assert {item["id"] for item in response.json()["items"]} == own
        assert [mark for mark in (*foreign, _B_MARKER) if mark in response.text] == []
        assert b_view.status_code == 200, b_view.text
        assert {item["id"] for item in b_view.json()["items"]} == foreign

    @covers(("DELETE", "/api/trash"))
    def test_cross_org_trash_empty_purges_only_the_callers_own_items(
        self, world: World, client: TestClient
    ) -> None:
        """A's Editor empties its trash: 200 ``{"chats": 1, "attachments": 1}``; org B's
        trashed rows, files on disk and audit rows stay as they were, and B's Editor
        still lists its two items."""
        _marked_trashed_chat(world, world.a["editor"], _A_MARKER)
        _marked_trashed_attachment(world, world.a["editor"], _A_MARKER)
        foreign = {
            str(_marked_trashed_chat(world, world.b["editor"], _B_MARKER)),
            str(_marked_trashed_attachment(world, world.b["editor"], _B_MARKER)),
        }
        before = _org_trash_state(world, world.org_b)

        response = client.delete("/api/trash", headers=world.a["editor"].cookie)

        assert (response.status_code, response.json()) == (200, {"chats": 1, "attachments": 1})
        assert _org_trash_state(world, world.org_b) == before
        b_view = client.get("/api/trash", headers=world.b["editor"].cookie)
        assert {item["id"] for item in b_view.json()["items"]} == foreign


_PLATFORM_USER_ACTIONS: Final[dict[str, int]] = {
    "deactivate": 200,
    "reactivate": 200,
    "password-reset": 202,
    "invitation": 200,
}
_PLATFORM_USER_PREFIX: Final = "/api/platform/orgs/{org_id}/users/{user_id}"
_B_FIRST_ADMIN: Final = "b-first-admin-167@example.ch"
_A_PLATFORM_INVITED: Final = "a-invited-167@example.ch"


def _platform_user_action(
    client: TestClient, caller: Account, org_id: uuid.UUID, user_id: str, action: str
) -> httpx.Response:
    """POST /api/platform/orgs/{org_id}/users/{user_id}/{action} as ``caller``, no body
    (a re-invite without a body resends)."""
    return client.post(
        f"/api/platform/orgs/{org_id}/users/{user_id}/{action}", headers=caller.cookie
    )


def _platform_target(world: World, action: str) -> str:
    """The org B account ``action`` applies to on org B's own path; its id.

    An active Editor (deactivate, password reset; it has a second session and a
    live reset token), a deactivated Editor (reactivate), or B's first Org
    Admin, still invited with a pending invitation, while neither org has an
    active Org Admin (re-invite: on org A's path a leaked target would be
    resent, not refused for another reason).
    """
    if action == "reactivate":
        return _deactivated(world, world.org_b, _B_DEACTIVATED)
    if action == "invitation":
        for members in (world.a, world.b):
            world.db.users[members["org_admin"].user_id]["status"] = "deactivated"
        invited = world.db.add_account(
            role="org_admin",
            org_id=world.org_b,
            status="invited",
            name=None,
            password_hash=None,
            email=_B_FIRST_ADMIN,
        )
        world.db.add_invitation(invited)
        return str(invited)
    editor = world.b["editor"].user_id
    world.db.open_session(editor)  # a second device
    world.db.add_reset_token(editor)
    return str(editor)


_PLATFORM_ACTION_PARAMS: Final = list(_PLATFORM_USER_ACTIONS)


class TestPlatformUserRoutes:
    """The Super Admin on org A's path with org B's accounts: 404, and nothing changes."""

    @pytest.mark.parametrize("kind", _FOREIGN_KINDS)
    @pytest.mark.parametrize("action", _PLATFORM_ACTION_PARAMS)
    def test_cross_org_platform_user_action_on_any_kind_of_other_org_account_is_404(
        self, world: World, client: TestClient, action: str, kind: str
    ) -> None:
        """B's last Org Admin, Editor, a deactivated user and an invited account are each
        a 404 "User not found" on org A's path, never a 409 (last_admin,
        invalid_status, seat_limit, has_active_admin) that would tell the account's
        state; nothing changes."""
        target = _foreign_account(world, kind)
        before = _state(world.db)

        response = _platform_user_action(client, world.super_admin, world.org_a, target, action)

        assert (response.status_code, response.json()) == (404, _USER_NOT_FOUND)
        assert _state(world.db) == before

    @pytest.mark.parametrize("action", _PLATFORM_ACTION_PARAMS)
    def test_cross_org_platform_user_action_answers_exactly_like_an_unknown_user(
        self, world: World, client: TestClient, action: str
    ) -> None:
        """No existence leak: org B's account on org A's path and a never-issued id get the
        same 404 body, and neither the body nor a header repeats B's id."""
        target = _platform_target(world, action)
        caller = world.super_admin

        foreign = _platform_user_action(client, caller, world.org_a, target, action)
        unknown = _platform_user_action(client, caller, world.org_a, str(uuid.uuid4()), action)

        assert (unknown.status_code, unknown.json()) == (404, _USER_NOT_FOUND)
        assert (foreign.status_code, foreign.json()) == (unknown.status_code, unknown.json())
        assert target not in foreign.text
        assert all(target not in value for value in foreign.headers.values())

    @pytest.mark.parametrize("action", _PLATFORM_ACTION_PARAMS)
    def test_cross_org_platform_user_action_keeps_the_other_orgs_user(
        self, world: World, client: TestClient, action: str
    ) -> None:
        """B's account keeps its row (status, role, email), its sessions, its reset token,
        its invitation (the link it was sent still works) and the queued emails; no audit
        row is written, and an active user is still logged in."""
        target = _platform_target(world, action)
        user_id = uuid.UUID(target)
        user_before = copy.deepcopy(world.db.users[user_id])
        sessions_before = sorted(str(row["session_id"]) for row in world.db.sessions_of(user_id))
        token_before = copy.deepcopy(world.db.tokens.get(user_id))
        invitation_before = copy.deepcopy(world.db.invitation_of(user_id))
        outbox_before = copy.deepcopy(world.db.outbox)
        audit_before = copy.deepcopy(world.db.audit_rows())

        response = _platform_user_action(client, world.super_admin, world.org_a, target, action)

        assert (response.status_code, response.json()) == (404, _USER_NOT_FOUND)
        assert world.db.users[user_id] == user_before
        assert sorted(str(row["session_id"]) for row in world.db.sessions_of(user_id)) == (
            sessions_before
        )
        assert world.db.tokens.get(user_id) == token_before
        assert world.db.invitation_of(user_id) == invitation_before
        assert world.db.outbox == outbox_before
        assert world.db.audit_rows() == audit_before
        if user_before["status"] == "active":
            assert len(sessions_before) == 2
            assert token_before is not None
            me = client.get("/api/auth/me", headers=world.b["editor"].cookie)
            assert me.status_code == 200, me.text

    @pytest.mark.parametrize("action", _PLATFORM_ACTION_PARAMS)
    def test_cross_org_platform_user_action_succeeds_on_the_users_own_org_path(
        self, world: World, client: TestClient, action: str
    ) -> None:
        """Control: after the 404 on org A's path, the same request on org B's path gets the
        route's success status (the path's org is the boundary, not a broken route)."""
        target = _platform_target(world, action)
        caller = world.super_admin

        refused = _platform_user_action(client, caller, world.org_a, target, action)
        response = _platform_user_action(client, caller, world.org_b, target, action)

        assert (refused.status_code, refused.json()) == (404, _USER_NOT_FOUND)
        assert response.status_code == _PLATFORM_USER_ACTIONS[action], response.text

    def test_cross_org_platform_users_list_and_metadata_hold_only_the_path_org(
        self, world: World, client: TestClient
    ) -> None:
        """Org A's users list has exactly A's accounts (active, deactivated, invited), no id
        or email of org B and not the Super Admin; A's seats count A's active and invited
        accounts against A's limit, whatever org B holds."""
        world.db.add_org(world.org_a, seats=12)
        a_off = _a_deactivated(world, client)
        a_invited = world.db.add_account(
            role="editor",
            org_id=world.org_a,
            status="invited",
            name=None,
            password_hash=None,
            email=_A_PLATFORM_INVITED,
        )
        world.db.add_invitation(a_invited)
        b_off = _b_deactivated(world, client)
        b_invited = _b_invited(world)
        for _ in range(3):
            world.db.add_account(role="editor", org_id=world.org_b)
        caller = world.super_admin

        users = client.get(f"/api/platform/orgs/{world.org_a}/users", headers=caller.cookie)
        metadata = client.get(f"/api/platform/orgs/{world.org_a}/metadata", headers=caller.cookie)

        assert users.status_code == 200, users.text
        a_ids = {str(account.user_id) for account in world.a.values()} | {a_off, str(a_invited)}
        assert {entry["id"] for entry in users.json()["users"]} == a_ids
        others = [
            b_off,
            b_invited,
            _B_DEACTIVATED,
            _B_INVITED,
            *(str(account.user_id) for account in world.b.values()),
            *(account.email for account in world.b.values()),
            str(caller.user_id),
            caller.email,
        ]
        assert [mark for mark in others if mark in users.text] == []
        assert metadata.status_code == 200, metadata.text
        assert metadata.json()["seats"] == {"used": 3, "limit": 12}


# ---------------------------------------------------------------------------
# 4. Completeness: every tenant route has a cross-org case here
# ---------------------------------------------------------------------------

_TENANT_ROUTES: Final = frozenset(
    (spec.method, spec.path) for spec in ROUTES if spec.isolation != "none"
)


def test_cross_org_every_tenant_route_has_a_cross_org_case() -> None:
    """Every ROUTES row with isolation != "none" is covered by a test of this file."""
    missing = sorted(_TENANT_ROUTES - set(_COVERED))

    assert not missing, (
        "These tenant routes have no cross-org case; add one to "
        f"tests/test_tenancy_cross_org.py (decorate it with @covers): {missing}"
    )


def test_cross_org_cases_cover_only_catalogued_tenant_routes() -> None:
    """No @covers names a route that isn't a tenant route of tests/tenancy_world.py ROUTES."""
    stale = sorted(set(_COVERED) - _TENANT_ROUTES)

    assert not stale, f"@covers names routes that aren't tenant ROUTES rows: {stale}"


def test_cross_org_every_path_id_route_has_a_path_id_case() -> None:
    """The path_id case table holds exactly the path_id rows of ROUTES."""
    path_id = {(spec.method, spec.path) for spec in ROUTES if spec.isolation == "path_id"}

    assert set(_PATH_ID_CASES) == path_id


def test_cross_org_coverage_names_real_tests() -> None:
    """Every registered case is a test of this module (the registry isn't a bare list)."""
    tests = {
        name
        for scope in (globals(), *(vars(cls) for cls in _CASE_CLASSES))
        for name in scope
        if name.startswith("test_cross_org_")
    }
    named = {name for names in _COVERED.values() for name in names}

    assert named
    assert named <= tests, sorted(named - tests)


@pytest.mark.usefixtures("world")
def test_cross_org_platform_user_cases_cover_every_registered_platform_user_route() -> None:
    """GH-167: the routes registered under /api/platform/orgs/{org_id}/users/{user_id}/
    are exactly the four actions TestPlatformUserRoutes covers (platform rows are
    isolation "none", so the @covers registry doesn't see them)."""
    registered = {
        (method, route.path)
        for route in make_app().routes
        if isinstance(route, APIRoute) and route.path.startswith(f"{_PLATFORM_USER_PREFIX}/")
        for method in route.methods
    }

    assert registered == {
        ("POST", f"{_PLATFORM_USER_PREFIX}/{action}") for action in _PLATFORM_USER_ACTIONS
    }


_CASE_CLASSES: Final = (
    TestPathIdRoutes,
    TestPathIdSideEffects,
    TestChatPathRoutes,
    TestChatRetryPathRoute,
    TestAttachmentPathRoutes,
    TestTrashPathRoutes,
    TestOwnOrgRoutes,
    TestOwnUserAccountRoutes,
    TestOwnUserOAuthRoutes,
    TestOwnUserChatRoutes,
    TestOwnUserTrashRoutes,
)
