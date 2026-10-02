"""Cross-org cases of the tenant isolation suite (GH-163, AC "Cross-org cases").

Org A's callers against org B's resources, through the real app, real session
cookies and the in-memory database of tests/db_fakes.py (the world of
tests/tenancy_world.py: two orgs, each with an Org Admin, an Editor and a
Viewer, plus a Super Admin):

- ``path_id`` routes (a resource id in the path, or the chat confirmation):
  another org's id answers 404 with exactly the body of an unknown id, never
  echoes the id, and changes nothing: no row, audit event, email, session,
  in-memory chat, pending confirmation or OAuth state. A control shows the
  caller reaches its own org's resource, and org B still reaches its own.
- ``own_org`` routes: org B is seeded differently from org A; org A's caller
  reads and changes only org A (settings, tool permissions, critical
  promotions, the permission summary, invitations, the user list).
- The org user routes of GH-164 (PATCH, deactivate, reactivate, DELETE,
  password reset): every kind of org B account (its last Org Admin, a member,
  a deactivated user, an invited account) is a 404 "User not found" for org
  A's Org Admin, never a 409 that would tell its state, and B's user keeps
  its row, sessions, connections, notes, settings, reset token, queued emails
  and in-memory state.
- ``own_user`` routes: only the caller's own data: sessions, settings, the
  account, logout, OAuth connections (and the data residency of the caller's
  own org), the in-memory chat history and the SSE stream.

Completeness: every test registers the routes it covers with ``@covers``. A
test asserts the covered set equals every ``ROUTES`` row whose isolation isn't
"none", so a later issue that adds a tenant route must add its case here.

Inputs: the FakeDb world, a stub agent (``agent.run`` is an AsyncMock), fake
OAuth client credentials and a fresh Fernet key per test.
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

from admino import oauth, org_permissions, server
from admino.models import LLMMessage, PendingConfirmation, ToolCall
from admino.oauth import encrypt_refresh_token
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    PASSWORD,
    ROUTES,
    Account,
    World,
    build_world,
    make_app,
    make_client,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
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
# One PATCH that changes every field the body allows: role, name and email.
_USER_PATCH: Final = {"role": "viewer", "name": "Umbenannt 164", "email": "renamed-164@example.ch"}
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
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (residency off) with their members and a Super Admin, in a FakeDb."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
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

    Every table, the sessions as token hash -> (user, session id) (any request
    may refresh the caller's ``last_seen_at``), plus the in-memory chats,
    pending confirmations, OAuth states and pending critical promotions.
    """
    tables = db.snapshot()
    sessions = tables.pop("sessions")
    tables["sessions"] = {
        token_hash: (str(row["user_id"]), str(row["session_id"]))
        for token_hash, row in sessions.items()
    }
    tables["chats"] = copy.deepcopy(dict(server._sessions))
    tables["pending_confirmations"] = copy.deepcopy(dict(server._pending_confirmations))
    tables["oauth_states"] = dict(server._oauth_pending_states)
    tables["promotions"] = dict(org_permissions._pending)
    return tables


def _invite(client: TestClient, admin: Account, email: str) -> str:
    """Invite ``email`` as an Editor into the admin's org over HTTP; the invitation id."""
    response = client.post(
        "/api/org/invitations", json={"email": email, "role": "editor"}, headers=admin.cookie
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _seed_pending(account: Account, chat_id: str, confirmation_id: str) -> None:
    """Store a live pending confirmation in one of the account's in-memory chats."""
    now = datetime.now(UTC)
    server._pending_confirmations[server._chat_key(account.user_id, chat_id)] = PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=chat_id,
        tool_call=ToolCall(tool="google_calendar", action="create", args={}),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _seed_chat(account: Account, chat_id: str, marker: str) -> tuple[uuid.UUID, str]:
    """Store an in-memory chat history of the account; return its chat key."""
    key: tuple[uuid.UUID, str] = server._chat_key(account.user_id, chat_id)
    server._sessions[key] = [
        LLMMessage(role="user", content=f"{marker} question"),
        LLMMessage(role="assistant", content=f"{marker} answer"),
    ]
    return key


def _confirm(
    client: TestClient, caller: Account, confirmation_id: str, chat_id: str
) -> httpx.Response:
    """Approve ``confirmation_id`` of the chat ``chat_id`` as ``caller``."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        json={"session_id": chat_id, "confirmation_id": confirmation_id, "approved": True},
        headers=caller.cookie,
    )


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


def _switch_off(db: FakeDb, org_id: uuid.UUID, *tools: str) -> None:
    """Switch tool services off in the org's existing org_settings row (build_world made it)."""
    row = db.org_settings[org_id]
    for tool in tools:
        row[f"{tool}_enabled"] = False


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
    stores org A's. ``send`` requests the route for an id as a caller.
    """

    caller: MemberRole
    detail: str
    own_status: int
    seed_foreign: Callable[[World, TestClient], str]
    seed_own: Callable[[World, TestClient], str]
    send: Callable[[TestClient, Account, str], httpx.Response]
    unknown_id: Callable[[], str]


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


def _deactivated(world: World, org_id: uuid.UUID, email: str) -> str:
    """A deactivated Viewer of the org (no session); its id."""
    return str(
        world.db.add_account(role="viewer", org_id=org_id, status="deactivated", email=email)
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
    """B's editor's pending confirmation; its chat id and confirmation id are the same."""
    _seed_pending(world.b["editor"], "b-pending-163", "b-pending-163")
    return "b-pending-163"


def _a_pending(world: World, _client: TestClient) -> str:
    _seed_pending(world.a["editor"], "a-pending-163", "a-pending-163")
    return "a-pending-163"


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
    ("PATCH", "/api/org/users/{user_id}"): _PathIdCase(
        caller="org_admin",
        detail="User not found",
        own_status=200,
        seed_foreign=_b_editor_id,
        seed_own=_a_editor_id,
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
}

_PATH_ID_PARAMS: Final = [
    pytest.param(route, id=f"{route[0]} {route[1]}") for route in _PATH_ID_CASES
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
_FOREIGN_KINDS: Final = ("org_admin", "editor", "viewer", "deactivated", "invited")


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

        assert (response.status_code, response.json()) == (404, {"detail": case.detail})

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
            {"detail": case.detail},
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
        """No row, audit event, email, session, chat, confirmation or state changes; no run."""
        case = _PATH_ID_CASES[route]
        foreign = case.seed_foreign(world, client)
        before = _state(world.db)

        response = case.send(client, world.a[case.caller], foreign)

        assert (response.status_code, response.json()) == (404, {"detail": case.detail})
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

        assert (response.status_code, response.json()) == (404, {"detail": case.detail})
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
        """B's last Org Admin, Editor, Viewer, a deactivated user and an invited account
        are each a 404 "User not found" for A's Org Admin, never a 409 (last_admin,
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
        in-memory chat, pending confirmation, OAuth state and cached access token; no
        email is queued, no audit row written, nothing revoked at a provider."""
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
        chat_key = server._chat_key(victim, _SHARED_CHAT)
        server._sessions[chat_key] = [LLMMessage(role="user", content="B-secret-164 question")]
        now = datetime.now(UTC)
        server._pending_confirmations[chat_key] = PendingConfirmation(
            confirmation_id="conf-b-164",
            session_id=_SHARED_CHAT,
            tool_call=ToolCall(tool="google_calendar", action="create", args={}),
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
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
        chat_before = copy.deepcopy(server._sessions[chat_key])

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
        assert server._sessions.get(chat_key) == chat_before
        assert server._pending_confirmations[chat_key].confirmation_id == "conf-b-164"
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
    def test_cross_org_confirm_with_the_other_orgs_chat_and_confirmation_ids_is_404(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """B's pending confirmation can't be approved by A's editor: 404, still pending, no run."""
        victim = world.b["editor"]
        _seed_pending(victim, _SHARED_CHAT, "conf-b-163")
        key = server._chat_key(victim.user_id, _SHARED_CHAT)
        pending_before = server._pending_confirmations[key].model_copy(deep=True)

        response = _confirm(client, world.a["editor"], "conf-b-163", _SHARED_CHAT)

        assert (response.status_code, response.json()) == (
            404,
            {"detail": "No pending confirmation for this session"},
        )
        assert server._pending_confirmations.get(key) == pending_before
        agent.run.assert_not_awaited()

    @covers(("POST", "/api/confirm/{confirmation_id}"))
    def test_cross_org_confirm_in_a_shared_chat_id_never_matches_the_other_orgs_confirmation(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """Both users have a pending in chat "shared-163": B's id is "Confirmation not found"
        for A, like an unknown id, and both pendings stay."""
        caller = world.a["editor"]
        _seed_pending(caller, _SHARED_CHAT, "conf-a-163")
        _seed_pending(world.b["editor"], _SHARED_CHAT, "conf-b-163")
        before = _state(world.db)

        foreign = _confirm(client, caller, "conf-b-163", _SHARED_CHAT)
        unknown = _confirm(client, caller, "conf-x-163", _SHARED_CHAT)

        assert (foreign.status_code, foreign.json()) == (404, {"detail": "Confirmation not found"})
        assert (unknown.status_code, unknown.json()) == (foreign.status_code, foreign.json())
        assert _state(world.db) == before
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
    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
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


# ---------------------------------------------------------------------------
# 3. own_user routes: only the caller's own data
# ---------------------------------------------------------------------------

_EVERYONE: Final = (
    "super_admin",
    "a.org_admin",
    "a.editor",
    "a.viewer",
    "b.org_admin",
    "b.editor",
    "b.viewer",
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
        assert [world.db.session_revoked(account.token) for account in others] == [False] * 6
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
    """The in-memory chats are keyed by (user, chat id): a shared chat id never crosses."""

    @covers(("POST", "/api/message"))
    def test_cross_org_message_with_the_other_orgs_chat_id_starts_an_empty_chat(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """A's editor sends to B's chat id: the run gets no history and A's principal only;
        B's stored history is unchanged."""
        victim_key = _seed_chat(world.b["editor"], _SHARED_CHAT, "B-secret-163")
        victim_before = copy.deepcopy(server._sessions[victim_key])
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
        assert server._sessions[victim_key] == victim_before
        assert "B-secret-163" not in response.text
        assert server._chat_key(caller.user_id, _SHARED_CHAT) in server._sessions

    @covers(("POST", "/api/message"))
    def test_cross_org_message_never_cancels_the_other_orgs_pending_confirmation(
        self, world: World, client: TestClient
    ) -> None:
        """A new message in A's chat "shared-163" leaves B's pending in that chat id."""
        victim = world.b["editor"]
        _seed_pending(victim, _SHARED_CHAT, "conf-b-163")
        key = server._chat_key(victim.user_id, _SHARED_CHAT)

        response = client.post(
            "/api/message",
            json={"message": "hello", "session_id": _SHARED_CHAT},
            headers=world.a["editor"].cookie,
        )

        assert response.status_code == 200, response.text
        assert key in server._pending_confirmations
        assert server._pending_confirmations[key].confirmation_id == "conf-b-163"

    @covers(("GET", "/api/events"))
    def test_cross_org_events_with_the_other_orgs_chat_id_streams_only_done(
        self, world: World, client: TestClient
    ) -> None:
        """A's stream of B's chat id is the empty chat's stream (no "connected" status)."""
        _seed_chat(world.b["editor"], _SHARED_CHAT, "B-secret-163")
        caller = world.a["editor"]

        a_stream = client.get(
            "/api/events", params={"session_id": _SHARED_CHAT}, headers=caller.cookie
        )
        empty = client.get(
            "/api/events", params={"session_id": "never-used-163"}, headers=caller.cookie
        )
        b_stream = client.get(
            "/api/events", params={"session_id": _SHARED_CHAT}, headers=world.b["editor"].cookie
        )

        assert a_stream.status_code == 200, a_stream.text
        assert a_stream.text == empty.text
        assert "event: done" in a_stream.text
        assert "connected" not in a_stream.text
        assert "B-secret-163" not in a_stream.text
        assert "connected" in b_stream.text  # control: B's own chat is live


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


_CASE_CLASSES: Final = (
    TestPathIdRoutes,
    TestPathIdSideEffects,
    TestOwnOrgRoutes,
    TestOwnUserAccountRoutes,
    TestOwnUserOAuthRoutes,
    TestOwnUserChatRoutes,
)
