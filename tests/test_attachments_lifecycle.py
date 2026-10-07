"""What happens to attachments when their chat, their owner or their org goes (GH-187).

Issue #187 ("Storage & access", "Org purge (from #154)", "Platform org metadata
(from #167)", Rescope "Deleting a user removes their files", Decisions 9, 12
and 14) and the contract's §3.3 to §3.6 and §4 pin:

- **Chat trash** (``DELETE /api/chats/{chat_id}``, Decision 12): every
  attachment of the chat gets ``deleted_at`` (contract A10; its place in the
  trash's transaction is pinned at the repository level in
  tests/test_chats_attachments.py). The files stay on disk (``<id>`` and the
  derived artifacts under ``<id>.d/``) until #194's purge.
  Afterwards the metadata and download routes answer ``404
  attachment_not_found`` for them and an upload into the chat ``404
  chat_not_found``; the owner's other chat keeps its attachment live and
  readable.
- **User deletion** (``DELETE /api/org/users/{user_id}`` by the Org Admin,
  Rescope + Decision 12, contract §3.5): the user's attachment rows go (the
  users row's cascade) and so do their files under
  ``attachments.attachments_root()``: ``<id>``, ``<id>.part`` and the whole
  ``<id>.d`` tree, of live and trashed chats alike. A colleague's and another
  org's rows and files, and a file of no row, stay. A11 (``SELECT id FROM
  attachments WHERE org_id = $1 AND owner_user_id = $2``) runs in the
  deletion's transaction, after the chat lock and before ``DELETE FROM
  users``; ``attachments.remove_files(root, org_id, ids)`` runs once, after the
  commit. A refused deletion (the last active Org Admin, 409) and a failed one
  (an audit failure, 500) remove no file; the same deletion succeeding later
  removes them.
- **Org purge** (#154): ``organizations.purge_due_orgs(pool,
  attachments_root=root)`` removes the due org's attachment files and derived
  artifacts with its directory; other orgs' files and rows stay. A regression
  guard: #154's purge already removes ``<root>/<org_id>``.
- **Platform org metadata** (#167, Decision 14, contract §3.6): ``GET
  /api/platform/orgs/{org_id}/metadata`` answers ``file_count`` = the number of
  the org's attachments and ``storage_used_bytes`` = the sum of their sizes,
  every status (uploaded, ready, failed) and trashed ones included; another
  org's never count; an org without files answers 0 and 0. Neither the
  response nor any statement it runs carries a file name (operator
  blindness).

Inputs: the world of tests/tenancy_world.py (orgs A and B, a member per role, a
Super Admin; real session cookies) over the FakeDb of tests/db_fakes.py, the
app from ``create_app()`` with a stub agent, and an attachments root under
``tmp_path`` (``organizations.ATTACHMENTS_ROOT`` patched, read at call time).
The new modules are imported inside the tests that need them.

Security notes: every id, name and byte is a fixed fake value; files live under
``tmp_path`` only. Tenant isolation: a deletion or a purge in one org never
touches another org's files, and the Super Admin sees counts, never names.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import organizations
from tests.db_fakes import OTHER_ORG_ID, FakeDb, plain
from tests.tenancy_world import (
    ATTACHMENT_NOT_FOUND,
    CHAT_NOT_FOUND,
    UPLOAD_BODY,
    Account,
    World,
    attachment_files,
    build_world,
    make_app,
    make_client,
    seed_attachment,
    seed_chat,
    upload_headers,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from fastapi.testclient import TestClient

    from tests.db_fakes import Call

_DAY_AGO: Final = datetime.now(UTC) - timedelta(days=1)
_LAST_ADMIN_REASON: Final = "last_admin"

# Contract §2's A11, normalized (lowercase, single spaces); the chat lock and the users
# DELETE of org_users.delete_org_user.
_A11_RE: Final = re.compile(
    r"select id from attachments where org_id = \$1 and owner_user_id = \$2"
)
_CHAT_LOCK_RE: Final = re.compile(r"^select id from chats where .* for update$")
_USERS_DELETE_RE: Final = re.compile(r"^delete from users\b")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root of the test (``organizations.ATTACHMENTS_ROOT``)."""
    return tmp_path / "attachments"


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, root: Path) -> World:
    """Orgs A and B with their members and a Super Admin; attachments under ``root``,
    both orgs with a storage quota."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, root)
    return built


@pytest.fixture()
def client(world: World) -> TestClient:
    """A client of the app, built after the world; a server error is a 500 response."""
    return make_client(make_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _one(items: Iterable[Any]) -> Any:
    found = list(items)
    assert len(found) == 1, found
    return found[0]


def _position(calls: list[Call], call: Call) -> int:
    """The index of this very call object in ``calls``."""
    return next(index for index, seen in enumerate(calls) if seen is call)


def _derived(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> None:
    """Derived artifacts (#188) of an attachment: a ``<id>.d`` tree with two files."""
    directory = root / str(org_id) / f"{attachment_id}.d"
    (directory / "pages").mkdir(parents=True)
    (directory / "text.md").write_bytes(b"# derived text 187\n")
    (directory / "pages" / "page-1.png").write_bytes(b"\x89PNG derived page 187")


def _part(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> None:
    """A leftover partial upload ``<id>.part`` of an attachment."""
    (root / str(org_id) / f"{attachment_id}.part").write_bytes(b"partial upload 187")


def _paths_of(files: dict[str, bytes], org_id: uuid.UUID, attachment_id: uuid.UUID) -> set[str]:
    """The keys of ``attachment_files()`` that belong to the attachment: its file, its
    ``.part`` and everything under its ``.d`` tree."""
    prefix = f"{org_id}/{attachment_id}"
    return {
        key for key in files if key in (prefix, f"{prefix}.part") or key.startswith(f"{prefix}.d/")
    }


def _deleted_at(world: World, attachment_id: uuid.UUID) -> datetime | None:
    row = world.db.attachment_row(attachment_id)
    assert row is not None, attachment_id
    deleted: datetime | None = row["deleted_at"]
    return deleted


# ---------------------------------------------------------------------------
# 1. Deleting a chat moves its attachments to the trash (Decision 12)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _TrashScene:
    """The Editor's chat with a sent (ready, with derived artifacts) and an unsent
    attachment, and the Editor's other chat with one attachment."""

    owner: Account
    chat_id: uuid.UUID
    sent: uuid.UUID
    unsent: uuid.UUID
    other_chat: uuid.UUID
    kept: uuid.UUID


def _trash_scene(world: World, root: Path) -> _TrashScene:
    owner = world.a["editor"]
    chat_id = seed_chat(
        world.db,
        owner,
        title="Papierkorb 187",
        messages=(("user", "Look at the file 187"), ("assistant", "Read it 187")),
    )
    message_id = plain(world.db.messages_of(chat_id)[0]["id"])
    sent = seed_attachment(
        world.db, chat_id, filename="sent-187.txt", status="ready", message_id=message_id
    )
    _derived(root, world.org_a, sent)
    unsent = seed_attachment(world.db, chat_id, filename="unsent-187.txt")
    other_chat = seed_chat(world.db, owner, title="Behalten 187")
    kept = seed_attachment(world.db, other_chat, filename="kept-187.txt", data=b"kept 187\n")
    return _TrashScene(owner, chat_id, sent, unsent, other_chat, kept)


class TestChatTrash:
    """DELETE /api/chats/{chat_id} trashes the chat's attachments; their files stay."""

    def test_attachments_lifecycle_chat_trash_trashes_its_attachments_and_keeps_their_files(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """Both of the chat's attachments (sent and unsent) get ``deleted_at``; the other
        chat's stays live; every file (the derived ``<id>.d`` tree included) stays as it
        was on disk."""
        scene = _trash_scene(world, root)
        files_before = attachment_files()

        response = client.delete(f"/api/chats/{scene.chat_id}", headers=scene.owner.cookie)

        assert response.status_code == 204, response.text
        assert {
            "sent": _deleted_at(world, scene.sent) is not None,
            "unsent": _deleted_at(world, scene.unsent) is not None,
            "other chat": _deleted_at(world, scene.kept) is not None,
        } == {"sent": True, "unsent": True, "other chat": False}
        assert attachment_files() == files_before
        assert len(_paths_of(files_before, world.org_a, scene.sent)) == 3

    def test_attachments_lifecycle_trashed_chats_attachments_are_no_longer_reachable(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """Before the trash the owner reads both routes (control); afterwards the trashed
        chat's attachments answer 404 attachment_not_found on the metadata and the
        download, an upload into the chat answers 404 chat_not_found, and the other
        chat's attachment still reads."""
        scene = _trash_scene(world, root)
        cookie = scene.owner.cookie

        def reads() -> dict[str, tuple[int, Any]]:
            seen: dict[str, tuple[int, Any]] = {}
            for label, attachment_id in (("sent", scene.sent), ("kept", scene.kept)):
                for suffix in ("", "/content"):
                    response = client.get(
                        f"/api/attachments/{attachment_id}{suffix}", headers=cookie
                    )
                    body = response.json() if response.status_code == 404 else None
                    seen[f"{label}{suffix}"] = (response.status_code, body)
            return seen

        before = reads()
        assert client.delete(f"/api/chats/{scene.chat_id}", headers=cookie).status_code == 204
        after = reads()
        upload = client.post(
            f"/api/chats/{scene.chat_id}/attachments",
            content=UPLOAD_BODY,
            headers={**upload_headers(), **cookie},
        )

        assert before == dict.fromkeys(
            ("sent", "sent/content", "kept", "kept/content"), (200, None)
        )
        assert after == {
            "sent": (404, ATTACHMENT_NOT_FOUND),
            "sent/content": (404, ATTACHMENT_NOT_FOUND),
            "kept": (200, None),
            "kept/content": (200, None),
        }
        assert (upload.status_code, upload.json()) == (404, CHAT_NOT_FOUND)


# ---------------------------------------------------------------------------
# 2. Deleting a user removes their files (Rescope, Decision 12, contract §3.5)
# ---------------------------------------------------------------------------


def _owned_attachments(
    world: World, root: Path, owner: uuid.UUID, label: str
) -> tuple[uuid.UUID, ...]:
    """Three attachments of ``owner`` (org A) with their files: one in a live chat with a
    leftover ``.part`` and derived artifacts, a second in the same chat, a third in a
    trashed chat (trashed too). Returns their ids."""
    live_chat = seed_chat(world.db, owner, title=f"{label} chat 187")
    first = seed_attachment(world.db, live_chat, filename=f"{label}-one-187.txt")
    _part(root, world.org_a, first)
    _derived(root, world.org_a, first)
    second = seed_attachment(world.db, live_chat, filename=f"{label}-two-187.txt")
    trashed_chat = world.db.add_chat(owner, title=f"{label} trashed 187", deleted_at=_DAY_AGO)
    third = seed_attachment(
        world.db, trashed_chat, filename=f"{label}-trashed-187.txt", deleted_at=_DAY_AGO
    )
    return first, second, third


@dataclass(frozen=True)
class _UserScene:
    """A fresh Editor of org A (the deletion's target) with three attachments, and the
    attachments of others that must stay: a colleague's (with derived artifacts), org
    B's, and a file under org A's directory that belongs to no row."""

    target: uuid.UUID
    owned: tuple[uuid.UUID, ...]
    others: tuple[uuid.UUID, ...]


def _user_scene(world: World, root: Path) -> _UserScene:
    target = world.db.add_account(
        role="editor", org_id=world.org_a, email="lifecycle-target-187@example.ch"
    )
    world.db.open_session(target)
    owned = _owned_attachments(world, root, target, "target")
    colleague_chat = seed_chat(world.db, world.a["editor"], title="Kollegin 187")
    colleague = seed_attachment(world.db, colleague_chat, filename="colleague-187.txt")
    _derived(root, world.org_a, colleague)
    org_b_chat = seed_chat(world.db, world.b["editor"], title="Org B 187")
    org_b = seed_attachment(world.db, org_b_chat, filename="org-b-187.txt")
    (root / str(world.org_a) / str(uuid.uuid4())).write_bytes(b"a file of no row 187")
    return _UserScene(target, owned, (colleague, org_b))


def _owned_paths(files: dict[str, bytes], org_id: uuid.UUID, ids: Iterable[uuid.UUID]) -> set[str]:
    """Every file of these attachments (their file, ``.part`` and ``.d`` tree)."""
    return {key for attachment_id in ids for key in _paths_of(files, org_id, attachment_id)}


class TestUserDeletion:
    """DELETE /api/org/users/{user_id}: the user's attachments go, rows and files."""

    def test_attachments_lifecycle_user_delete_removes_the_users_rows_and_files(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """The target's three rows are gone, and so is every file of theirs: ``<id>``,
        ``<id>.part`` and the ``<id>.d`` tree (the directory too), live and trashed
        chats alike."""
        scene = _user_scene(world, root)
        owned_paths = _owned_paths(attachment_files(), world.org_a, scene.owned)

        response = client.delete(
            f"/api/org/users/{scene.target}", headers=world.a["org_admin"].cookie
        )

        assert response.status_code == 204, response.text
        assert [world.db.attachment_row(attachment_id) for attachment_id in scene.owned] == [
            None,
            None,
            None,
        ]
        assert len(owned_paths) == 6
        assert owned_paths & set(attachment_files()) == set()
        assert not os.path.lexists(root / str(world.org_a) / f"{scene.owned[0]}.d")

    def test_attachments_lifecycle_user_delete_keeps_everyone_elses_rows_and_files(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """Afterwards the files are exactly the colleague's (with its derived artifacts),
        org B's and the file of no row; the colleague's and org B's rows are unchanged."""
        scene = _user_scene(world, root)
        files_before = attachment_files()
        owned_paths = _owned_paths(files_before, world.org_a, scene.owned)
        rows_before = {other: world.db.attachment_row(other) for other in scene.others}

        response = client.delete(
            f"/api/org/users/{scene.target}", headers=world.a["org_admin"].cookie
        )

        assert response.status_code == 204, response.text
        assert attachment_files() == {
            key: data for key, data in files_before.items() if key not in owned_paths
        }
        assert {other: world.db.attachment_row(other) for other in scene.others} == rows_before

    def test_attachments_lifecycle_user_delete_refused_for_the_last_admin_removes_no_file(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """Org A's only active Org Admin deletes themselves: 409 last_admin, their rows
        and files stay. With a second active Org Admin the same deletion succeeds and
        removes them (control)."""
        admin = world.a["org_admin"]
        owned = _owned_attachments(world, root, admin.user_id, "admin")
        files_before = attachment_files()
        rows_before = [world.db.attachment_row(attachment_id) for attachment_id in owned]

        refused = client.delete(f"/api/org/users/{admin.user_id}", headers=admin.cookie)
        kept = (
            attachment_files() == files_before,
            [world.db.attachment_row(attachment_id) for attachment_id in owned] == rows_before,
        )
        world.db.add_account(
            role="org_admin", org_id=world.org_a, email="second-admin-187@example.ch"
        )
        done = client.delete(f"/api/org/users/{admin.user_id}", headers=admin.cookie)

        assert (refused.status_code, refused.json().get("reason")) == (409, _LAST_ADMIN_REASON)
        assert kept == (True, True)
        assert done.status_code == 204, done.text
        assert _owned_paths(files_before, world.org_a, owned) & set(attachment_files()) == set()

    def test_attachments_lifecycle_user_delete_audit_failure_removes_no_file(
        self, world: World, client: TestClient, root: Path
    ) -> None:
        """The user.delete audit write fails: 500, the target and their rows and files
        stay (a rolled-back deletion removes nothing). Retried without the failure, the
        deletion removes them (control)."""
        scene = _user_scene(world, root)
        files_before = attachment_files()
        world.db.fail_audit = True

        failed = client.delete(
            f"/api/org/users/{scene.target}", headers=world.a["org_admin"].cookie
        )
        kept = (
            scene.target in world.db.users,
            attachment_files() == files_before,
            all(world.db.attachment_row(attachment_id) for attachment_id in scene.owned),
        )
        world.db.fail_audit = False
        done = client.delete(f"/api/org/users/{scene.target}", headers=world.a["org_admin"].cookie)

        assert failed.status_code == 500
        assert kept == (True, True, True)
        assert done.status_code == 204, done.text
        assert (
            _owned_paths(files_before, world.org_a, scene.owned) & set(attachment_files()) == set()
        )

    def test_attachments_lifecycle_user_delete_collects_ids_in_its_transaction_removes_after(
        self, world: World, client: TestClient, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A11, bound to (org, user), runs on the deletion's connection and transaction,
        after the chat lock and before DELETE FROM users. ``attachments.remove_files``
        runs once, after that transaction committed, with the attachments root, the org
        and exactly the user's attachment ids."""
        from admino import attachments, org_users

        scene = _user_scene(world, root)
        real_remove = attachments.remove_files
        removals: list[tuple[Any, uuid.UUID, list[uuid.UUID], list[Any]]] = []

        async def spy(
            root_arg: Path, org_id: uuid.UUID, attachment_ids: Iterable[uuid.UUID]
        ) -> int:
            ids = [plain(attachment_id) for attachment_id in attachment_ids]
            removals.append((root_arg, plain(org_id), sorted(ids), list(world.db.transactions)))
            removed: int = await real_remove(root_arg, org_id, ids)
            return removed

        monkeypatch.setattr(attachments, "remove_files", spy)
        monkeypatch.setattr(org_users, "remove_files", spy, raising=False)
        mark = len(world.db.calls)

        response = client.delete(
            f"/api/org/users/{scene.target}", headers=world.a["org_admin"].cookie
        )

        calls = world.db.calls[mark:]
        lock = _one(call for call in calls if _CHAT_LOCK_RE.search(call.normalized))
        a11 = _one(call for call in calls if _A11_RE.fullmatch(call.normalized))
        delete = _one(call for call in calls if _USERS_DELETE_RE.search(call.normalized))
        assert response.status_code == 204, response.text
        assert delete.tx is not None
        assert {(call.via, call.tx) for call in (lock, a11, delete)} == {(delete.via, delete.tx)}
        assert _position(calls, lock) < _position(calls, a11) < _position(calls, delete)
        assert [plain(arg) for arg in a11.args] == [world.org_a, scene.target]
        assert [(str(entry[0]), entry[1], entry[2]) for entry in removals] == [
            (str(root), world.org_a, sorted(scene.owned))
        ]
        assert (delete.tx, "commit") in removals[0][3]


# ---------------------------------------------------------------------------
# 3. Purging an org removes its attachment files (#154, regression guard)
# ---------------------------------------------------------------------------


class TestOrgPurge:
    """purge_due_orgs removes the due org's attachment files and derived artifacts."""

    async def test_attachments_lifecycle_org_purge_removes_the_orgs_files_and_artifacts(
        self, monkeypatch: pytest.MonkeyPatch, root: Path
    ) -> None:
        """A due org's attachments (a file with derived artifacts, one with a leftover
        ``.part``, a trashed one) are gone from disk with its directory, and their rows
        with the org; an active org's attachment rows and files stay as they were."""
        root.mkdir(parents=True)
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
        db = FakeDb()
        now = datetime.now(UTC)
        due = db.add_org(
            status="pending_deletion",
            deletion_requested_at=now - timedelta(days=30, minutes=1),
            purge_after=now - timedelta(minutes=1),
        )
        kept_org = db.add_org(OTHER_ORG_ID)
        due_member = db.add_account(role="editor", org_id=due, email="purged-187@example.ch")
        kept_member = db.add_account(role="editor", org_id=kept_org, email="kept-187@example.ch")
        due_chat = db.add_chat(due_member, title="Purged chat 187")
        trashed_chat = db.add_chat(due_member, title="Purged trash 187", deleted_at=_DAY_AGO)
        with_artifacts = seed_attachment(db, due_chat, filename="purged-one-187.txt")
        _derived(root, due, with_artifacts)
        with_part = seed_attachment(db, due_chat, filename="purged-two-187.txt")
        _part(root, due, with_part)
        seed_attachment(db, trashed_chat, filename="purged-three-187.txt", deleted_at=_DAY_AGO)
        kept_chat = db.add_chat(kept_member, title="Kept chat 187")
        kept = seed_attachment(db, kept_chat, filename="kept-org-187.txt")
        _derived(root, kept_org, kept)
        kept_files = {
            key: data for key, data in attachment_files().items() if key.startswith(f"{kept_org}/")
        }
        kept_row = db.attachment_row(kept)

        purged = await organizations.purge_due_orgs(db.pool, attachments_root=root)

        assert purged == 1
        assert not os.path.lexists(root / str(due))
        assert attachment_files() == kept_files
        assert len(kept_files) == 3
        assert [plain(key) for key in db.attachments] == [kept]
        assert db.attachment_row(kept) == kept_row


# ---------------------------------------------------------------------------
# 4. The Super Admin's org metadata counts files and bytes (#167, Decision 14)
# ---------------------------------------------------------------------------

_ZEPHYR_NAME: Final = "Zephyrmarker Vertragsentwurf 187.pdf"


def _metadata(client: TestClient, world: World, org_id: uuid.UUID) -> dict[str, Any]:
    """The Super Admin's GET /api/platform/orgs/{org_id}/metadata body (asserted 200)."""
    response = client.get(f"/api/platform/orgs/{org_id}/metadata", headers=world.super_admin.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _files_and_bytes(body: dict[str, Any]) -> tuple[Any, Any]:
    return body["file_count"], body["storage_used_bytes"]


def _org_a_attachments(world: World) -> None:
    """Org A's four attachments, 7300 bytes: a ready one sent with a message (1000), a
    failed one (2000), an unsent upload (300) and one in a trashed chat (4000)."""
    chat_id = seed_chat(
        world.db, world.a["editor"], title="Metadaten 187", messages=(("user", "Files 187"),)
    )
    message_id = plain(world.db.messages_of(chat_id)[0]["id"])
    seed_attachment(
        world.db,
        chat_id,
        filename="ready-187.txt",
        data=b"r" * 1000,
        status="ready",
        message_id=message_id,
    )
    seed_attachment(
        world.db,
        chat_id,
        filename="failed-187.txt",
        data=b"f" * 2000,
        status="failed",
        failure_reason="corrupted_file",
    )
    seed_attachment(world.db, chat_id, filename="unsent-187.txt", data=b"u" * 300)
    trashed_chat = world.db.add_chat(
        world.a["org_admin"].user_id, title="Trashed 187", deleted_at=_DAY_AGO
    )
    seed_attachment(
        world.db, trashed_chat, filename="trashed-187.txt", data=b"t" * 4000, deleted_at=_DAY_AGO
    )


class TestPlatformOrgMetadata:
    """file_count and storage_used_bytes are the org's attachments, never its names."""

    def test_attachments_lifecycle_platform_metadata_counts_every_attachment_of_the_org(
        self, world: World, client: TestClient
    ) -> None:
        """Ready, failed, unsent and trashed attachments all count: 4 files, 7300 bytes
        (integers); the response keys are unchanged."""
        _org_a_attachments(world)

        body = _metadata(client, world, world.org_a)

        assert _files_and_bytes(body) == (4, 7300)
        assert [type(value) for value in _files_and_bytes(body)] == [int, int]
        assert set(body) == {"seats", "storage_used_bytes", "chat_count", "file_count"}

    def test_attachments_lifecycle_platform_metadata_counts_only_the_orgs_own_files(
        self, world: World, client: TestClient
    ) -> None:
        """Org B (two files, 50,007 bytes) counts its own, never org A's; org A counts
        none of B's; an org without files answers 0 and 0."""
        _org_a_attachments(world)
        org_b_chat = seed_chat(world.db, world.b["editor"], title="Org B 187")
        seed_attachment(world.db, org_b_chat, filename="b-large-187.txt", data=b"b" * 50_000)
        seed_attachment(world.db, org_b_chat, filename="b-small-187.txt", data=b"b" * 7)
        org_c = world.db.add_org(name="Org C 187", storage_quota_bytes=1024)

        counts = {
            label: _files_and_bytes(_metadata(client, world, org_id))
            for label, org_id in (("a", world.org_a), ("b", world.org_b), ("c", org_c))
        }

        assert counts == {"a": (4, 7300), "b": (2, 50_007), "c": (0, 0)}

    def test_attachments_lifecycle_platform_metadata_never_names_a_file(
        self, world: World, client: TestClient
    ) -> None:
        """A file with a distinctive name counts (1 file, its size), but the name is
        nowhere in the response, and no statement of the request reads a file name."""
        chat_id = seed_chat(world.db, world.a["editor"], title="Vertraulich 187")
        seed_attachment(world.db, chat_id, filename=_ZEPHYR_NAME, kind="pdf", data=b"%PDF-1.7 187")
        mark = len(world.db.calls)

        response = client.get(
            f"/api/platform/orgs/{world.org_a}/metadata", headers=world.super_admin.cookie
        )

        assert response.status_code == 200, response.text
        assert _files_and_bytes(response.json()) == (1, len(b"%PDF-1.7 187"))
        assert "zephyrmarker" not in response.text.lower()
        assert [
            call.normalized for call in world.db.calls[mark:] if "filename" in call.normalized
        ] == []
