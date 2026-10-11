"""HTTP-layer spec of the retired Viewer role (GH-306).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py through the tenancy world of tests/tenancy_world.py (orgs A
and B with an Org Admin and an Editor each, plus a Super Admin; real session
cookies resolved by the real ``require_session``). Argon2 is a fast fake and
every rate-limit bucket is roomy.

What these tests pin down (issue #306, criteria "API and policy" and "docs",
Decisions 7 and 10, and the Tests section's fourth bullet):
- The two routes that take a role (Decision 7: ``POST /api/org/invitations``
  and ``PATCH /api/org/users/{user_id}``) answer ``viewer`` with ``422`` in the
  existing validation envelope: exactly one error ``{"loc": ["body",
  "role"], "msg": "Input isn't one of the allowed values", "type":
  "literal_error"}`` (GH-302's fixed text). Nothing is written, audited,
  emailed or counted as a seat; next to a valid name change the name stays.
- Guards: ``org_admin`` and ``editor`` are still accepted on both routes.
- The API contract (``app.openapi()``, served as ``/api/openapi.json`` behind
  a session): every ``role`` enum of the member-role request and response
  schemas is exactly ``["org_admin", "editor"]``, and no schema lists the
  retired role anywhere.
- Reactivating a retired Viewer (the state migration 0034 leaves: a
  deactivated ``editor`` with no session and the migration's ``system``
  ``user.deactivate`` row, ``{"reason": "viewer_retired",
  "sessions_revoked": 0}``) is an explicit grant of Editor: ``200`` with role
  ``editor`` and status ``active``, exactly one new ``user.activate`` row by
  the Org Admin, then the account logs in and holds Editor rights (it creates
  a chat, it can't list the org's users).
- No Markdown file under ``docs/`` mentions the word (``\\bviewers?\\b``, any
  case); the failure names each file and line.

Security notes: every id, email and name here is a fixed fake value. No
network, no real PostgreSQL, no SMTP, no LLM.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import database
from tests.db_fakes import ORG_ID, FakeDb, fake_hash
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    PASSWORD,
    SESSION_COOKIE,
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import Iterator

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INVITES: Final = "/api/org/invitations"
_USERS: Final = "/api/org/users"
_SAME_ORIGIN: Final = {"Sec-Fetch-Site": "same-origin"}
_RETIRED_ROLE: Final = "viewer"
_MEMBER_ROLES: Final = ("org_admin", "editor")
_INVITE_EMAIL: Final = "new.member.306@example.ch"
_NEW_NAME: Final = "Renamed Member 306"
_RETIRED_EMAIL: Final = "former.reader.306@example.ch"
_RETIRED_NAME: Final = "Former Reader 306"

# GH-302's fixed text of a literal_error; one error at the role field.
_ROLE_REFUSED: Final = {
    "detail": [
        {
            "loc": ["body", "role"],
            "msg": "Input isn't one of the allowed values",
            "type": "literal_error",
        }
    ]
}

# Every schema of the contract whose ``role`` is a member role (requests, then responses).
_ROLE_SCHEMAS: Final = (
    "InvitationCreateRequest",
    "OrgUserPatch",
    "MeResponse",
    "OrgUserSummary",
    "InvitationSummary",
    "InvitationDetails",
    "PlatformUserSummary",
)

# What the seeded "retired Viewer" mirrors in the shipped migration (Decisions 1 to 3):
# the audit action, actor and metadata, and the role and status the account is left with.
_MIGRATION_LEAVES: Final = (
    r"['\"]user\.deactivate['\"]",
    r"['\"]system['\"]",
    r"['\"]viewer_retired['\"]",
    r"['\"]sessions_revoked['\"]",
    r"\brole\s*=\s*'editor'",
    r"\bstatus\s*=\s*'deactivated'",
)

_DOCS: Final = Path(__file__).resolve().parent.parent / "docs"
_RETIRED_WORD: Final = re.compile(r"\bviewers?\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (an Org Admin and an Editor each) and a Super Admin behind the fake
    database; fast passwords; every rate-limit bucket roomy."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def client(world: World) -> TestClient:
    """The app (a stub agent) and a client at ``CLIENT_IP``."""
    return make_client(make_app())


def _state(db: FakeDb) -> dict[str, Any]:
    """Every table; sessions without ``last_seen_at`` (any request refreshes it)."""
    tables = db.snapshot()
    tables["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in tables["sessions"].items()
    }
    return tables


def _headers(cookie: dict[str, str]) -> dict[str, str]:
    """A session cookie plus the same-origin header a browser sends on a write."""
    return {**cookie, **_SAME_ORIGIN}


def _invite(client: TestClient, world: World, role: str) -> httpx.Response:
    """POST /api/org/invitations as org A's Org Admin."""
    return client.post(
        _INVITES,
        json={"email": _INVITE_EMAIL, "role": role},
        headers=_headers(world.a["org_admin"].cookie),
    )


def _patch(client: TestClient, world: World, user_id: object, body: object) -> httpx.Response:
    """PATCH /api/org/users/{user_id} as org A's Org Admin."""
    return client.patch(
        f"{_USERS}/{user_id}", json=body, headers=_headers(world.a["org_admin"].cookie)
    )


def _seats_used(client: TestClient, world: World) -> int:
    """Org A's used seats as GET /api/org/users reports them to its Org Admin."""
    response = client.get(_USERS, headers=world.a["org_admin"].cookie)
    assert response.status_code == 200, response.text
    used: int = response.json()["seats"]["used"]
    return used


def _session_cookie(response: httpx.Response) -> dict[str, str]:
    """Request headers carrying the session cookie a login response set."""
    values = [
        header.split(";", 1)[0].split("=", 1)[1]
        for header in response.headers.get_list("set-cookie")
        if header.lower().startswith(f"{SESSION_COOKIE}=")
    ]
    assert len(values) == 1, response.headers.get_list("set-cookie")
    return {"Cookie": f"{SESSION_COOKIE}={values[0]}"}


def _role_enums(node: Any) -> list[list[Any]]:
    """Every ``enum`` list inside a property schema (``anyOf`` branches included)."""
    if isinstance(node, dict):
        found = [node["enum"]] if "enum" in node else []
        for key, value in node.items():
            if key != "enum":
                found.extend(_role_enums(value))
        return found
    if isinstance(node, list):
        return [enum for item in node for enum in _role_enums(item)]
    return []


def _texts(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every (path, text) of a JSON document: each dict key and each string value."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield f"{path}/{key}", str(key)
            yield from _texts(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _texts(item, f"{path}/{index}")
    elif isinstance(node, str):
        yield path, node


def _shipped_retirement_sql() -> str:
    """The one shipped migration that retires the role (0034, renumbered if needed)."""
    directory = Path(database.__file__).parent / "migrations"
    paths = sorted(directory.glob("[0-9][0-9][0-9][0-9]_retire_viewer_role.sql"))
    assert len(paths) == 1, f"one shipped NNNN_retire_viewer_role.sql expected: {paths}"
    return paths[0].read_text(encoding="utf-8")


def _seed_retired_viewer(db: FakeDb) -> uuid.UUID:
    """The state migration 0034 leaves for a former Viewer of org A: a deactivated Editor
    with no session and the migration's system ``user.deactivate`` row."""
    user_id = db.add_account(
        role="editor",
        status="deactivated",
        org_id=ORG_ID,
        email=_RETIRED_EMAIL,
        name=_RETIRED_NAME,
        password_hash=fake_hash(PASSWORD),
    )
    db.add_audit(
        org_id=ORG_ID,
        action="user.deactivate",
        actor_kind="system",
        target_type="user",
        target_ids=(user_id,),
        metadata={"reason": "viewer_retired", "sessions_revoked": 0},
    )
    return user_id


# ---------------------------------------------------------------------------
# 1. POST /api/org/invitations refuses the retired role
# ---------------------------------------------------------------------------


def test_viewer_role_retired_api_invitation_with_viewer_role_is_422(
    world: World, client: TestClient
) -> None:
    """422 with one literal_error at ["body", "role"]; no users or invitations row, no
    queued email, no audit row, no seat taken."""
    seats_before = _seats_used(client, world)
    before = _state(world.db)

    response = _invite(client, world, _RETIRED_ROLE)

    assert response.status_code == 422, response.text
    assert response.json() == _ROLE_REFUSED
    assert world.db.user_by_email(_INVITE_EMAIL) is None
    assert _state(world.db) == before
    assert _seats_used(client, world) == seats_before


@pytest.mark.parametrize("role", _MEMBER_ROLES)
def test_viewer_role_retired_api_invitation_with_member_role_is_201(
    world: World, client: TestClient, role: str
) -> None:
    """Guard: both member roles are still accepted; the invited account holds the role."""
    response = _invite(client, world, role)

    assert response.status_code == 201, response.text
    assert response.json()["role"] == role
    row = world.db.user_by_email(_INVITE_EMAIL)
    assert row is not None
    assert (row["role"], row["status"]) == (role, "invited")


# ---------------------------------------------------------------------------
# 2. PATCH /api/org/users/{user_id} refuses the retired role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"role": _RETIRED_ROLE}, id="role-only"),
        pytest.param({"role": _RETIRED_ROLE, "name": _NEW_NAME}, id="next-to-a-name-change"),
    ],
)
def test_viewer_role_retired_api_user_patch_with_viewer_role_is_422(
    world: World, client: TestClient, body: dict[str, str]
) -> None:
    """422 with one literal_error at ["body", "role"]; the target keeps its role and name,
    nothing is audited or written."""
    target = world.a["editor"].user_id
    name_before = world.db.users[target]["name"]
    before = _state(world.db)

    response = _patch(client, world, target, body)

    assert response.status_code == 422, response.text
    assert response.json() == _ROLE_REFUSED
    assert (world.db.users[target]["role"], world.db.users[target]["name"]) == (
        "editor",
        name_before,
    )
    assert _state(world.db) == before


@pytest.mark.parametrize("role", _MEMBER_ROLES)
def test_viewer_role_retired_api_user_patch_with_member_role_is_200(
    world: World, client: TestClient, role: str
) -> None:
    """Guard: both member roles are still a change: org A's Editor made Org Admin, and a
    second Org Admin of org A made Editor (org A keeps its first Org Admin)."""
    if role == "org_admin":
        target = world.a["editor"].user_id
    else:
        target = world.db.add_account(role="org_admin", org_id=ORG_ID)

    response = _patch(client, world, target, {"role": role})

    assert response.status_code == 200, response.text
    assert response.json()["role"] == role
    assert world.db.users[target]["role"] == role


# ---------------------------------------------------------------------------
# 3. The API contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("schema", _ROLE_SCHEMAS)
def test_viewer_role_retired_api_openapi_role_enum_is_the_two_member_roles(schema: str) -> None:
    """The schema's ``role`` property lists exactly ["org_admin", "editor"] (a nullable
    role through its anyOf branch)."""
    schemas = make_app().openapi()["components"]["schemas"]

    assert _role_enums(schemas[schema]["properties"]["role"]) == [["org_admin", "editor"]]


def test_viewer_role_retired_api_openapi_lists_no_viewer() -> None:
    """No schema mentions the retired role in any key, enum, default or description, and
    no part of the document (paths and parameters included) has it as a value."""
    document = make_app().openapi()

    in_schemas = [
        (path, text)
        for path, text in _texts(document["components"]["schemas"], "/components/schemas")
        if _RETIRED_WORD.search(text)
    ]
    as_values = [
        (path, text) for path, text in _texts(document) if text.strip().casefold() == "viewer"
    ]

    assert set(_ROLE_SCHEMAS) <= set(document["components"]["schemas"])
    assert (in_schemas, as_values) == ([], [])


# ---------------------------------------------------------------------------
# 4. Reactivating a retired Viewer is an explicit grant of Editor
# ---------------------------------------------------------------------------


def test_viewer_role_retired_api_reactivated_former_viewer_is_an_active_editor(
    world: World, client: TestClient
) -> None:
    """The seeded state is the shipped migration's; org A's Org Admin reactivates it: 200
    (role editor, status active), the row is an active Editor, exactly one new
    user.activate row by the Org Admin (the migration's row kept); the account then logs
    in, is an Editor member of org A, creates a chat and can't list the org's users."""
    sql = _shipped_retirement_sql()
    assert [pattern for pattern in _MIGRATION_LEAVES if not re.search(pattern, sql)] == []
    db = world.db
    retired = _seed_retired_viewer(db)
    admin = world.a["org_admin"]
    audit_before = copy.deepcopy(db.audit)

    response = client.post(f"{_USERS}/{retired}/reactivate", headers=_headers(admin.cookie))

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["id"], body["role"], body["status"]) == (str(retired), "editor", "active")
    assert (db.users[retired]["role"], db.users[retired]["status"]) == ("editor", "active")
    assert db.audit[: len(audit_before)] == audit_before
    assert [
        (
            row["action"],
            row["actor_kind"],
            str(row["actor_user_id"]),
            str(row["org_id"]),
            row["target_type"],
            row["target_ids"],
            row["ip"],
            row["metadata"],
        )
        for row in db.audit[len(audit_before) :]
    ] == [
        (
            "user.activate",
            "member",
            str(admin.user_id),
            str(ORG_ID),
            "user",
            [str(retired)],
            CLIENT_IP,
            {},
        )
    ]

    client.cookies.clear()
    login = client.post(
        "/api/auth/login",
        json={"email": _RETIRED_EMAIL, "password": PASSWORD},
        headers=_SAME_ORIGIN,
    )
    assert login.status_code == 204, login.text
    cookie = _session_cookie(login)
    client.cookies.clear()
    me = client.get("/api/auth/me", headers=cookie)
    chat = client.post("/api/chats", json={}, headers=_headers(cookie))
    users = client.get(_USERS, headers=cookie)

    assert (me.status_code, me.json()["kind"], me.json()["org_id"], me.json()["role"]) == (
        200,
        "member",
        str(ORG_ID),
        "editor",
    )
    assert chat.status_code == 201, chat.text
    assert (users.status_code, users.json()) == (403, FORBIDDEN)


# ---------------------------------------------------------------------------
# 5. The docs
# ---------------------------------------------------------------------------


def test_viewer_role_retired_api_docs_never_mention_the_retired_role() -> None:
    """No line of any Markdown file under docs/ (recursively) matches ``\\bviewers?\\b`` in
    any case; each hit is reported as ``<file>:<line>: <text>``."""
    paths = sorted(_DOCS.rglob("*.md"))
    hits = [
        f"{path.relative_to(_DOCS.parent)}:{number}: {line.strip()}"
        for path in paths
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if _RETIRED_WORD.search(line)
    ]

    assert paths, f"no Markdown file under {_DOCS}"
    assert hits == []
