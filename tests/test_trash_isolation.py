"""Tenant isolation of the trash (GH-194, Decision 1 "Scope", Decision 6 "Routes").

The trash is its owner's own in V1: every trash route acts on the caller's own
items only. This file pins what the generic tenancy suite (tests/test_tenancy*.py,
whose rows and builders cover each route's 401, role, per-user bucket and
org A -> org B 404 cases) can't say on its own:

- Across orgs, in the other direction too: org B's Org Admin never sees org A's
  trash in ``GET /api/trash`` (and org A's Editor never sees B's), gets the
  ``chat_not_found`` / ``attachment_not_found`` 404 of an unknown id on restore
  and delete forever of org A's items, and ``DELETE /api/trash`` empties only B's
  own trash: org A's rows, files on disk (originals and derived ``<id>.d/``) and
  audit log are unchanged, and the owner still reaches each item afterwards.
- Within an org (Decision 1): an Org Admin's request on an Editor's item is the
  same 404 as an unknown id (and an Editor's on the Org Admin's), the Org
  Admin's list holds only its own items, and the Org Admin's ``DELETE
  /api/trash`` purges only its own; the Editor's items stay reachable after
  each refusal.
- Roles: the Super Admin gets ``403 {"detail": "Forbidden"}`` on all seven
  trash routes and nothing changes (GH-306: every member role has
  ``chat.send``; an Editor whose ``chat.send`` is refused is pinned on each
  trash route in tests/test_tenancy_roles.py).
- No response, log record (DEBUG, JSON, as an operator would see it) or audit
  row of these refusals names the other user's chat title or file name.

Harness: the world of tests/tenancy_world.py (orgs A and B with an Org Admin
and an Editor each, a Super Admin; real session cookies) over the
FakeDb of tests/db_fakes.py, the app from ``create_app()`` with a stub agent,
and a per-test attachments root under ``tmp_path``. Each owner's trash is a
trashed chat (a message, a file trashed with it), a file it deleted on its own
from a live chat, and a live file of that chat (``DELETE
/api/attachments/{attachment_id}``), seeded with ``deleted_at`` one hour ago
(the default retention is 30 days).

Security notes: titles and file names are fixed canary values (they are
content: they must never reach a log line or an audit row); every id, email and
password is a fixed fake value or generated per test; nothing leaves the host.
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import pytest

from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    ATTACHMENT_NOT_FOUND,
    CHAT_NOT_FOUND,
    FORBIDDEN,
    Account,
    World,
    attachment_files,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_attachment,
    seed_chat,
    seed_trashed_attachment,
    seed_trashed_chat,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import MemberRole, Role

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (residency off, 30-day trash retention) with their members and a
    Super Admin in a FakeDb; attachments under ``tmp_path``."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def agent() -> MagicMock:
    """The stub agent (it must never run here)."""
    return stub_agent()


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app, built after the world (create_app clears the in-memory state)."""
    return make_client(make_app(agent))


# ---------------------------------------------------------------------------
# Seeds: one owner's trash, every name a canary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Trash:
    """One owner's seeded trash and the live file next to it."""

    owner: Account
    marker: str
    chat_id: uuid.UUID
    group_file_id: uuid.UUID
    file_id: uuid.UUID
    live_file_id: uuid.UUID

    @property
    def items(self) -> set[str]:
        """The ids ``GET /api/trash`` lists: the trashed chat and the file of its own."""
        return {str(self.chat_id), str(self.file_id)}

    @property
    def names(self) -> tuple[str, ...]:
        """The canaries: the trashed chat's title and every file name."""
        return (
            f"{self.marker} Vertragsentwurf",
            f"{self.marker} Anhang.txt",
            f"{self.marker} Papierkorb.txt",
            f"{self.marker} Live.txt",
        )


def _seed_trash(world: World, owner: Account, marker: str) -> _Trash:
    """Seed ``owner``'s trash: a trashed chat (a question, a file trashed with it), a live
    chat holding a file deleted on its own and a live file; every name carries ``marker``."""
    title, group_name, own_name, live_name = (
        f"{marker} Vertragsentwurf",
        f"{marker} Anhang.txt",
        f"{marker} Papierkorb.txt",
        f"{marker} Live.txt",
    )
    chat_id = seed_trashed_chat(
        world.db,
        owner,
        title=title,
        messages=(("user", f"{marker} Frage"),),
        filenames=(group_name,),
    )
    live_chat_id = seed_chat(world.db, owner, title=f"{marker} Laufend")
    return _Trash(
        owner=owner,
        marker=marker,
        chat_id=chat_id,
        group_file_id=uuid.UUID(str(world.db.attachments_of(chat_id)[0]["id"])),
        file_id=seed_trashed_attachment(
            world.db, live_chat_id, filename=own_name, data=f"{marker} Inhalt\n".encode()
        ),
        live_file_id=seed_attachment(
            world.db, live_chat_id, filename=live_name, data=f"{marker} Live\n".encode()
        ),
    )


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ItemRoute:
    """A trash route on one item: method, path prefix and suffix, the item it names,
    its 404 body and its success status on the owner's own item."""

    method: str
    prefix: str
    suffix: str
    item: str
    not_found: dict[str, str]
    own_status: int

    def url(self, ident: str) -> str:
        """The route's URL for ``ident``."""
        return f"{self.prefix}{ident}{self.suffix}"

    def target(self, trash: _Trash) -> str:
        """The id of ``trash``'s item this route names."""
        return str(getattr(trash, self.item))


_ITEM_ROUTES: Final[dict[str, _ItemRoute]] = {
    "restore-chat": _ItemRoute(
        "POST", "/api/trash/chats/", "/restore", "chat_id", CHAT_NOT_FOUND, 200
    ),
    "delete-forever-chat": _ItemRoute(
        "DELETE", "/api/trash/chats/", "", "chat_id", CHAT_NOT_FOUND, 204
    ),
    "restore-file": _ItemRoute(
        "POST", "/api/trash/attachments/", "/restore", "file_id", ATTACHMENT_NOT_FOUND, 200
    ),
    "delete-forever-file": _ItemRoute(
        "DELETE", "/api/trash/attachments/", "", "file_id", ATTACHMENT_NOT_FOUND, 204
    ),
}
_ITEM_PARAMS: Final = list(_ITEM_ROUTES)


def _send(client: TestClient, caller: Account, route: _ItemRoute, ident: str) -> httpx.Response:
    """Send ``route`` for ``ident`` as ``caller`` (no body)."""
    response: httpx.Response = client.request(route.method, route.url(ident), headers=caller.cookie)
    return response


def _every_trash_request(target: _Trash) -> dict[str, tuple[str, str]]:
    """All seven trash routes as (method, URL), the item routes naming ``target``'s items."""
    return {
        "GET /api/trash": ("GET", "/api/trash"),
        "DELETE /api/trash": ("DELETE", "/api/trash"),
        "DELETE /api/attachments": ("DELETE", f"/api/attachments/{target.live_file_id}"),
        **{
            name: (route.method, route.url(route.target(target)))
            for name, route in _ITEM_ROUTES.items()
        },
    }


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


def _state(world: World) -> dict[str, Any]:
    """Every table (sessions without their ``last_seen_at`` refresh), the audit log,
    the chat runtime and every file under the attachments root."""
    tables = world.db.snapshot()
    tables["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in tables["sessions"].items()
    }
    tables["chat_runtime"] = chat_runtime_state(world.db)
    tables["files"] = attachment_files()
    return tables


def _owned(world: World, owner: Account) -> dict[str, Any]:
    """``owner``'s chats, chat messages and attachments rows (trashed ones included), its
    files under the attachments root and the audit rows naming it as actor, as copies."""
    tables = world.db.snapshot()
    user = str(owner.user_id)
    chats = sorted(
        (row for row in tables["chats"].values() if str(row["owner_user_id"]) == user),
        key=lambda row: str(row["id"]),
    )
    chat_ids = {str(row["id"]) for row in chats}
    attachments = sorted(
        (row for row in tables["attachments"].values() if str(row["chat_id"]) in chat_ids),
        key=lambda row: str(row["id"]),
    )
    prefixes = tuple(f"{owner.org_id}/{row['id']}" for row in attachments)
    return {
        "chats": chats,
        "messages": sorted(
            (row for row in tables["chat_messages"].values() if str(row["chat_id"]) in chat_ids),
            key=lambda row: str(row["id"]),
        ),
        "attachments": attachments,
        "files": {
            path: data for path, data in attachment_files().items() if path.startswith(prefixes)
        },
        "audit": [
            copy.deepcopy(row) for row in world.db.audit_rows() if str(row["actor_user_id"]) == user
        ],
    }


def _listed(client: TestClient, caller: Account) -> set[str]:
    """The ids in ``caller``'s ``GET /api/trash`` (first page, 100 items)."""
    response = client.get("/api/trash", params={"limit": "100"}, headers=caller.cookie)
    assert response.status_code == 200, response.text
    return {item["id"] for item in response.json()["items"]}


# ---------------------------------------------------------------------------
# 1. Across orgs: org B's member on org A's trash
# ---------------------------------------------------------------------------


class TestCrossOrgTrash:
    """Org A's trash is out of org B's reach, and B's out of A's."""

    def test_trash_isolation_list_never_shows_the_other_orgs_items_in_either_direction(
        self, world: World, client: TestClient
    ) -> None:
        """Org A's Editor and org B's Org Admin each have a trash: each lists exactly its
        own two items, and neither response names the other's ids, title or file names."""
        a_trash = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        b_trash = _seed_trash(world, world.b["org_admin"], "Quokka-B-194")

        a_view = client.get("/api/trash", headers=a_trash.owner.cookie)
        b_view = client.get("/api/trash", headers=b_trash.owner.cookie)

        assert (a_view.status_code, b_view.status_code) == (200, 200), a_view.text
        assert (
            {item["id"] for item in a_view.json()["items"]},
            {item["id"] for item in b_view.json()["items"]},
        ) == (a_trash.items, b_trash.items)
        leaks = [
            mark
            for view, other in ((a_view, b_trash), (b_view, a_trash))
            for mark in (*other.items, other.marker)
            if mark in view.text
        ]
        assert leaks == []

    @pytest.mark.parametrize("route_name", _ITEM_PARAMS)
    def test_trash_isolation_other_orgs_org_admin_on_an_item_is_404_and_changes_nothing(
        self, world: World, client: TestClient, agent: MagicMock, route_name: str
    ) -> None:
        """Org B's Org Admin restoring or deleting forever org A's Editor's item: the 404
        of an unknown id (same body and content type), no row, file or audit row of either
        org changes, A's marker never appears; A's Editor then reaches the item."""
        route = _ITEM_ROUTES[route_name]
        a_trash = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        intruder = world.b["org_admin"]
        before = _state(world)

        foreign = _send(client, intruder, route, route.target(a_trash))
        unknown = _send(client, intruder, route, str(uuid.uuid4()))
        after = _state(world)
        owner = _send(client, a_trash.owner, route, route.target(a_trash))

        assert (foreign.status_code, foreign.json()) == (404, route.not_found)
        assert (unknown.status_code, unknown.json()) == (404, route.not_found)
        assert foreign.headers.get("content-type") == unknown.headers.get("content-type")
        assert after == before
        assert a_trash.marker not in foreign.text
        assert owner.status_code == route.own_status, owner.text
        agent.run.assert_not_awaited()

    def test_trash_isolation_other_orgs_empty_trash_never_purges_the_callers_items(
        self, world: World, client: TestClient
    ) -> None:
        """Org B's Org Admin empties its own trash: 200 with its own counts; org A's
        Editor's rows, files on disk (originals and derived files) and audit rows are as
        they were, and A's Editor still lists its two items."""
        a_trash = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        _seed_trash(world, world.b["org_admin"], "Quokka-B-194")
        before = _owned(world, a_trash.owner)

        response = client.delete("/api/trash", headers=world.b["org_admin"].cookie)

        assert (response.status_code, response.json()) == (200, {"chats": 1, "attachments": 1})
        assert _owned(world, a_trash.owner) == before
        assert len(before["files"]) == 5
        assert _listed(client, a_trash.owner) == a_trash.items


# ---------------------------------------------------------------------------
# 2. Within an org: an Org Admin doesn't reach an Editor's trash (Decision 1)
# ---------------------------------------------------------------------------

_COLLEAGUES: Final = [
    pytest.param("org_admin", "editor", id="org-admin-on-editors-item"),
    pytest.param("editor", "org_admin", id="editor-on-org-admins-item"),
]


class TestColleagueTrash:
    """Owner-only V1 scope: a colleague's trash item is an unknown item, even for an Org
    Admin; the org-wide trash comes with #185."""

    def test_trash_isolation_org_admin_lists_only_its_own_trash(
        self, world: World, client: TestClient
    ) -> None:
        """Org A's Org Admin and Editor each have a trash: the Org Admin lists only its
        own two items (none of the Editor's, no colleague's name), the Editor only its
        own."""
        admin = _seed_trash(world, world.a["org_admin"], "Admin-A-194")
        editor = _seed_trash(world, world.a["editor"], "Zephyr-A-194")

        admin_view = client.get("/api/trash", headers=admin.owner.cookie)

        assert admin_view.status_code == 200, admin_view.text
        assert {item["id"] for item in admin_view.json()["items"]} == admin.items
        assert editor.marker not in admin_view.text
        assert _listed(client, editor.owner) == editor.items

    @pytest.mark.parametrize(("caller_role", "owner_role"), _COLLEAGUES)
    @pytest.mark.parametrize("route_name", _ITEM_PARAMS)
    def test_trash_isolation_colleagues_item_is_404_like_an_unknown_id(
        self,
        world: World,
        client: TestClient,
        route_name: str,
        caller_role: MemberRole,
        owner_role: MemberRole,
    ) -> None:
        """A colleague's trashed chat or file (an Org Admin's request on an Editor's item
        included): the 404 of an unknown id, nothing changes (rows, files, audit, the chat
        runtime), the colleague's names and the id never appear; the owner then reaches
        the item with the route's success status."""
        route = _ITEM_ROUTES[route_name]
        target = _seed_trash(world, world.a[owner_role], "Zephyr-A-194")
        caller = world.a[caller_role]
        before = _state(world)

        colleague = _send(client, caller, route, route.target(target))
        unknown = _send(client, caller, route, str(uuid.uuid4()))
        after = _state(world)
        owner = _send(client, target.owner, route, route.target(target))

        assert (colleague.status_code, colleague.json()) == (404, route.not_found)
        assert (unknown.status_code, unknown.json()) == (404, route.not_found)
        assert colleague.headers.get("content-type") == unknown.headers.get("content-type")
        assert after == before
        assert [
            mark for mark in (target.marker, route.target(target)) if mark in colleague.text
        ] == []
        assert owner.status_code == route.own_status, owner.text

    def test_trash_isolation_org_admin_empty_trash_purges_only_its_own_items(
        self, world: World, client: TestClient
    ) -> None:
        """The Org Admin's ``DELETE /api/trash`` purges its own trashed chat (with its file)
        and its file of its own (rows and files gone), answers ``{"chats": 1,
        "attachments": 1}``, and leaves the Editor's rows, files and audit rows as they
        were; the Editor then empties its own (the same counts)."""
        admin = _seed_trash(world, world.a["org_admin"], "Admin-A-194")
        editor = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        before = _owned(world, editor.owner)

        emptied = client.delete("/api/trash", headers=admin.owner.cookie)
        editor_after = _owned(world, editor.owner)
        admin_rows = (
            world.db.chat_row(admin.chat_id),
            world.db.attachment_row(admin.group_file_id),
            world.db.attachment_row(admin.file_id),
        )
        own = client.delete("/api/trash", headers=editor.owner.cookie)

        assert (emptied.status_code, emptied.json()) == (200, {"chats": 1, "attachments": 1})
        assert editor_after == before
        assert admin_rows == (None, None, None)
        assert (own.status_code, own.json()) == (200, {"chats": 1, "attachments": 1})


# ---------------------------------------------------------------------------
# 3. Roles: the Super Admin gets 403
# ---------------------------------------------------------------------------


class TestRefusedRoles:
    """``chat.send`` gates every trash route: the Super Admin is refused before anything
    is read or changed."""

    @pytest.mark.parametrize("role", ["super_admin"])
    def test_trash_isolation_refused_role_gets_403_on_every_trash_route_and_nothing_changes(
        self, world: World, client: TestClient, role: Role
    ) -> None:
        """The Super Admin naming org A's Editor's items: ``403 {"detail": "Forbidden"}``
        on all seven routes, and no row, file, audit row or runtime entry changes."""
        caller = world.by_role(role)
        target = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        requests = _every_trash_request(target)
        before = _state(world)

        answers = {
            name: (response.status_code, response.json())
            for name, (method, url) in requests.items()
            for response in [client.request(method, url, headers=caller.cookie)]
        }

        assert answers == dict.fromkeys(requests, (403, FORBIDDEN))
        assert _state(world) == before


# ---------------------------------------------------------------------------
# 4. No refusal names the other user's title or file name
# ---------------------------------------------------------------------------


class TestRefusalsLeakNothing:
    """Responses, log records and audit rows of the refusals carry no content."""

    def test_trash_isolation_refusals_never_name_the_other_users_title_or_file_name(
        self, world: World, client: TestClient
    ) -> None:
        """Org B's Org Admin, org A's Org Admin and the Super Admin send every trash route
        on org A's Editor's items (and list and empty their own trash): the expected
        refusals, and the Editor's chat title and file names appear in no response, no
        log line (DEBUG, JSON) and no audit row."""
        target = _seed_trash(world, world.a["editor"], "Zephyr-A-194")
        requests = _every_trash_request(target)
        callers = {
            "b-org-admin": world.b["org_admin"],
            "a-org-admin": world.a["org_admin"],
            "super-admin": world.super_admin,
        }
        refused = {
            "b-org-admin": 404,
            "a-org-admin": 404,
            "super-admin": 403,
        }

        with configured_logging("DEBUG", "json") as captured:
            responses = {
                (who, name): client.request(method, url, headers=caller.cookie)
                for who, caller in callers.items()
                for name, (method, url) in requests.items()
            }

        expected = {
            (who, name): (
                200
                if who != "super-admin" and name in {"GET /api/trash", "DELETE /api/trash"}
                else refused[who]
            )
            for who, name in responses
        }
        audit = json.dumps(world.db.audit_rows(), default=str)
        texts = {
            "responses": " ".join(response.text for response in responses.values()),
            "logs": captured.text,
            "audit": audit,
        }
        assert {key: response.status_code for key, response in responses.items()} == expected
        assert captured.records != []
        assert {
            where: [name for name in target.names if name in text] for where, text in texts.items()
        } == {"responses": [], "logs": [], "audit": []}
