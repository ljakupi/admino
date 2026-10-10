"""Tests for GH-265: every users deletion locks the affected chats in id order first.

GH-66's org-wide promotion notice (``chats.append_org_notice``) locks the org's
live chats ``ORDER BY id FOR UPDATE`` and then inserts into chat_messages,
whose org_id foreign key takes a ``FOR KEY SHARE`` lock on the org row. A
``DELETE FROM users`` cascades to the user's chats and locks them in physical
scan order, so a deletion and a notice running at the same time could lock
the same chats in opposite orders and deadlock (``40P01``). The fix: every
path that deletes users rows first locks the chats the cascade will delete,
``SELECT id FROM chats WHERE ... ORDER BY id FOR UPDATE``, bound to the org,
on the same connection and in the same transaction, before the delete.

What these tests pin down (``tests/db_fakes.py``'s FakeDb runs every
statement; no real PostgreSQL):
- ``org_users.delete_org_user``: exactly one chat lock, bound to the actor's
  org and the target (``org_id`` and ``owner_user_id``, no deletion-state
  filter: trashed chats are cascaded too), after the last-admin guard and the
  target's row lock and before ``DELETE FROM users``, in the committed
  transaction of the delete. A refused deletion (the last active Org Admin,
  an unknown, another org's or an invited user) issues no chat lock and
  changes nothing.
- ``organizations.purge_due_orgs``: the chat lock (bound to the due org only)
  is the FIRST statement of the org's transaction, before the org row's
  locked re-check (``FOR UPDATE``), so the purge can't hold the org row while
  waiting for chats the notice holds. An org cancelled concurrently still
  counts 0 and loses nothing.
- ``invitations.revoke_pending_invitation`` (through ``revoke_invitation``
  and through the Super Admin's re-invite with a replacement email): the chat
  lock binds the invitation and the org, matches only the chats of that
  pending invitation's account in that org and runs right before the users
  DELETE. An invitation of another org, an unknown id or an accepted one is
  still ``InvitationNotFoundError`` with nothing changed (the lock matches no
  chat).
- The rows each lock statement selects are exactly the chats the cascade
  deletes: never a colleague's, never another org's.
- Unchanged behaviour: the same cascades (the deleted users' chats and their
  messages, trashed ones included), the same audit events and metadata, the
  same return values; nothing is logged. A deletion without chats works as
  before.
- Fail closed: a failure of the chat lock rolls the whole deletion back.
- With the notice (sequentially, the FakeDb has no real row locks): a
  deletion before or after a notice leaves exactly one notice in every
  remaining live chat of the org, none in a trashed or another org's chat,
  and both lock the shared chats in the same order.

Security notes:
- Tenant isolation at the data layer: every lock statement binds the org id;
  a deletion in one org locks no chat of another org.
- No content in logs: the deletions log nothing.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import accounts, chats, invitations, org_users, organizations, platform_users
from admino.access import Principal
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, norm, plain

if TYPE_CHECKING:
    from pathlib import Path

    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.65"
_NOTICE: Final = "The Org Admin enabled a new tool for the organization."
_NEW_EMAIL: Final = "Grace.Replacement.Gh265@Example.ch"
_CREATED: Final = datetime.now(UTC) - timedelta(days=3)
_TRASHED: Final = _CREATED + timedelta(days=1)

# The ordered chat lock (the notice's S12a form): SELECT id FROM chats WHERE ...
# ORDER BY id FOR UPDATE, waiting (no SKIP LOCKED / NOWAIT).
_CHAT_LOCK_RE: Final = re.compile(
    r"select (?:\w+\.)?id from chats(?: (?:as )?(?!where\b)\w+)? where (?P<where>.+)"
    r" order by (?:\w+\.)?id for update"
)
# fail_sql pattern for the chat lock (and nothing else these paths run).
_CHAT_LOCK_FAIL: Final = r"^select (?:\w+\.)?id from chats\b.* for update$"
_BIND_ATOM_RE: Final = re.compile(r"(?:\w+\.)?(?P<column>\w+) = \$(?P<n>\d+)(?: ?:: ?uuid)?")
_OWNER_SUBQUERY_RE: Final = re.compile(
    r"(?:\w+\.)?owner_user_id = \(select (?:\w+\.)?user_id from invitations"
    r"(?: (?:as )?(?!where\b)\w+)? where (?P<where>.+)\)"
)
_USERS_DELETE_RE: Final = r"^delete from users\b"
_GUARD_RE: Final = r"\bas is_active_admin from users\b"
_REFUSALS: Final = ("last-admin", "unknown", "other-org", "invited")
_NOT_FOUND: Final = ("other-org", "unknown", "accepted")
_ENTRIES: Final = ("org-admin-revoke", "super-admin-replace")
_MOMENTS: Final = ("after-due-lookup", "after-chat-lock")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Lock:
    """One chat-lock statement and the chat ids it selects, in its order."""

    call: Call
    chat_ids: list[uuid.UUID]


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root of the purge tests (an empty directory)."""
    path = tmp_path / "attachments"
    path.mkdir()
    return path


@pytest.fixture()
def locks(db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> list[_Lock]:
    """Every ordered chat-lock statement run on the fake, with the rows it selects.

    The rows are read through the fake's SQL reader right after the statement
    ran (whatever asyncpg method issued it), on the same state.
    """
    seen: list[_Lock] = []
    handle = db.handle

    def spy(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        result = handle(method, sql, args, via, tx)
        normalized = norm(sql)
        if _CHAT_LOCK_RE.fullmatch(normalized):
            call = db.calls[-1]
            rows = db._run_statement("fetch", normalized, args)
            seen.append(_Lock(call, [plain(row["id"]) for row in rows]))
        return result

    monkeypatch.setattr(db, "handle", spy)
    return seen


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _position(db: FakeDb, call: Call) -> int:
    """The index of this very call object in db.calls."""
    return next(index for index, seen in enumerate(db.calls) if seen is call)


def _in_tx(db: FakeDb, call: Call) -> list[Call]:
    """The calls on the same connection and transaction as ``call``, in order."""
    return [seen for seen in db.calls if (seen.via, seen.tx) == (call.via, call.tx)]


def _split_and(text: str) -> list[str]:
    """The AND-ed atoms of a WHERE clause, split at parenthesis depth 0."""
    atoms: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text.startswith(" and ", index):
            atoms.append(text[start:index].strip())
            index += len(" and ")
            start = index
            continue
        index += 1
    atoms.append(text[start:].strip())
    return atoms


def _predicates(where: str, args: tuple[Any, ...]) -> tuple[dict[str, Any], list[str]]:
    """``<column> = $n`` atoms as {column: bound value}, and the other atoms as text."""
    bound: dict[str, Any] = {}
    other: list[str] = []
    for atom in _split_and(where):
        match = _BIND_ATOM_RE.fullmatch(atom)
        if match is None:
            other.append(atom)
            continue
        value = args[int(match["n"]) - 1]
        bound[match["column"]] = plain(value) if isinstance(value, uuid.UUID) else value
    return bound, other


def _lock_predicates(call: Call) -> tuple[dict[str, Any], list[str]]:
    """The chat lock's WHERE atoms (see ``_predicates``)."""
    match = _CHAT_LOCK_RE.fullmatch(call.normalized)
    assert match is not None, call.normalized
    return _predicates(match["where"], call.args)


def _chat_ids(db: FakeDb) -> set[uuid.UUID]:
    return {plain(chat_id) for chat_id in db.chats}


def _chat_state(db: FakeDb, chat_ids: list[uuid.UUID]) -> dict[uuid.UUID, Any]:
    """Each chat's row and messages, for "kept unchanged" checks."""
    return {chat_id: (db.chat_row(chat_id), db.messages_of(chat_id)) for chat_id in chat_ids}


def _gone(db: FakeDb, chat_ids: list[uuid.UUID]) -> bool:
    """Neither the chats nor any of their messages are stored."""
    wanted = set(chat_ids)
    return all(db.chat_row(chat_id) is None for chat_id in chat_ids) and not any(
        plain(row["chat_id"]) in wanted for row in db.chat_messages.values()
    )


def _notices(db: FakeDb, chat_id: uuid.UUID) -> int:
    """How many copies of the notice the chat holds (a user message, status complete)."""
    return sum(
        1
        for row in db.messages_of(chat_id)
        if (row["role"], row["content"], row["status"]) == ("user", _NOTICE, "complete")
    )


def _admino_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name.startswith("admino")]


def _member(
    db: FakeDb, *, org_id: uuid.UUID = ORG_ID, role: str = "editor", **fields: Any
) -> uuid.UUID:
    return db.add_account(org_id=org_id, role=role, **fields)


def _invited(db: FakeDb, *, org_id: uuid.UUID = ORG_ID, role: str = "org_admin") -> uuid.UUID:
    """An invited account with a pending invitation."""
    user_id = _member(db, org_id=org_id, role=role, status="invited", name=None, password_hash=None)
    db.add_invitation(user_id)
    return user_id


def _invitation_id(db: FakeDb, user_id: uuid.UUID) -> uuid.UUID:
    row = db.invitation_of(user_id)
    assert row is not None
    return plain(row["id"])


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    row = db.users[user_id]
    return Principal(user_id=user_id, kind="member", org_id=row["org_id"], role=row["role"])


def _chats_of(
    db: FakeDb, owner: uuid.UUID, *, live: int = 2, trashed: int = 1
) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
    """Live and trashed chats of the owner, each holding a user and an assistant message."""
    made: tuple[list[uuid.UUID], list[uuid.UUID]] = ([], [])
    for index in range(live + trashed):
        is_trashed = index >= live
        chat_id = db.add_chat(
            owner, created_at=_CREATED, deleted_at=_TRASHED if is_trashed else None
        )
        db.add_chat_message(chat_id, "user", "Hello")
        db.add_chat_message(chat_id, "assistant", "Hi there")
        made[int(is_trashed)].append(chat_id)
    return made


# ---------------------------------------------------------------------------
# Worlds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _OrgWorld:
    """ORG_ID: the Org Admin (one live chat), the target (two live, one trashed, two
    sessions) and a colleague (two live, one trashed); OTHER_ORG_ID: an outsider
    (two live, one trashed)."""

    admin_id: uuid.UUID
    admin: Principal
    target: uuid.UUID
    colleague: uuid.UUID
    target_live: list[uuid.UUID]
    target_trashed: list[uuid.UUID]
    org_live: list[uuid.UUID]
    org_trashed: list[uuid.UUID]
    foreign: list[uuid.UUID]

    @property
    def target_chats(self) -> list[uuid.UUID]:
        return [*self.target_live, *self.target_trashed]

    @property
    def kept_chats(self) -> list[uuid.UUID]:
        return [*self.org_live, *self.org_trashed, *self.foreign]


def _org_world(db: FakeDb) -> _OrgWorld:
    admin_id = _member(db, role="org_admin")
    target = _member(db)
    colleague = _member(db, role="editor")
    outsider = _member(db, org_id=OTHER_ORG_ID, role="org_admin")
    db.open_session(target)
    db.open_session(target)
    admin_live, _ = _chats_of(db, admin_id, live=1, trashed=0)
    target_live, target_trashed = _chats_of(db, target)
    colleague_live, colleague_trashed = _chats_of(db, colleague)
    foreign_live, foreign_trashed = _chats_of(db, outsider)
    return _OrgWorld(
        admin_id=admin_id,
        admin=_principal(db, admin_id),
        target=target,
        colleague=colleague,
        target_live=target_live,
        target_trashed=target_trashed,
        org_live=[*admin_live, *colleague_live],
        org_trashed=colleague_trashed,
        foreign=[*foreign_live, *foreign_trashed],
    )


async def _delete(db: FakeDb, actor: Principal, user_id: Any) -> Any:
    return await org_users.delete_org_user(db.pool, actor=actor, user_id=user_id, ip=_IP)


@dataclass(frozen=True)
class _PurgeWorld:
    """A due org whose users (active, deactivated, soft-deleted, invited) own live and
    trashed chats; an active ORG_ID member and an OTHER_ORG_ID member own kept chats."""

    org_id: uuid.UUID
    users: list[uuid.UUID]
    org_chats: list[uuid.UUID]
    kept_chats: list[uuid.UUID]


def _due_org(db: FakeDb) -> uuid.UUID:
    """A pending_deletion org whose purge date passed a minute ago."""
    now = datetime.now(UTC)
    return db.add_org(
        status="pending_deletion",
        deletion_requested_at=now - timedelta(days=30, minutes=1),
        purge_after=now - timedelta(minutes=1),
    )


def _purge_world(db: FakeDb, *, with_chats: bool = True) -> _PurgeWorld:
    org_id = _due_org(db)
    admin = _member(db, org_id=org_id, role="org_admin")
    deactivated = _member(db, org_id=org_id, status="deactivated")
    soft_deleted = _member(db, org_id=org_id, deleted_at=_TRASHED)
    invited = _invited(db, org_id=org_id, role="editor")
    users = [admin, deactivated, soft_deleted, invited]
    org_chats: list[uuid.UUID] = []
    if with_chats:
        for owner, live, trashed in ((admin, 2, 1), (deactivated, 1, 0), (soft_deleted, 0, 1)):
            owner_live, owner_trashed = _chats_of(db, owner, live=live, trashed=trashed)
            org_chats += [*owner_live, *owner_trashed]
    kept: list[uuid.UUID] = []
    for owner in (_member(db), _member(db, org_id=OTHER_ORG_ID)):
        owner_live, owner_trashed = _chats_of(db, owner)
        kept += [*owner_live, *owner_trashed]
    return _PurgeWorld(org_id, users, org_chats, kept)


async def _purge(db: FakeDb, root: Path) -> Any:
    return await organizations.purge_due_orgs(db.pool, attachments_root=root)


def _locks_the_org(call: Call, org_id: uuid.UUID) -> bool:
    """Whether the call reads the org's organizations row FOR UPDATE."""
    return (
        re.search(r"\bfrom organizations\b", call.normalized) is not None
        and re.search(r"\bfor (?:no key )?update\b", call.normalized) is not None
        and org_id in [plain(arg) for arg in call.args if isinstance(arg, uuid.UUID)]
    )


@dataclass(frozen=True)
class _RevokeWorld:
    """ORG_ID with an invited Org Admin (pending invitation) and an active colleague
    (two live, one trashed chat); an OTHER_ORG_ID member (two live, one trashed).
    ``actor`` is an active Org Admin of ORG_ID (revoke) or a Super Admin (re-invite
    with a replacement email; the org then has no active Org Admin)."""

    entry: str
    actor: Principal
    invited: uuid.UUID
    invitation_id: uuid.UUID
    invited_chats: list[uuid.UUID]
    kept_chats: list[uuid.UUID]


def _revoke_world(db: FakeDb, entry: str, *, invited_chats: bool = False) -> _RevokeWorld:
    if entry == "org-admin-revoke":
        actor = _principal(db, _member(db, role="org_admin"))
    else:
        actor = Principal(user_id=db.add_account(kind="super_admin", role=None), kind="super_admin")
    invited = _invited(db)
    owned: list[uuid.UUID] = []
    if invited_chats:
        # The database doesn't forbid it (an invited account can't log in, so it
        # has none in practice): it proves the lock covers exactly the cascade.
        live, trashed = _chats_of(db, invited)
        owned = [*live, *trashed]
    kept: list[uuid.UUID] = []
    for owner in (_member(db), _member(db, org_id=OTHER_ORG_ID)):
        live, trashed = _chats_of(db, owner)
        kept += [*live, *trashed]
    return _RevokeWorld(entry, actor, invited, _invitation_id(db, invited), owned, kept)


async def _revoke(db: FakeDb, world: _RevokeWorld) -> Any:
    if world.entry == "org-admin-revoke":
        return await invitations.revoke_invitation(
            db.pool, actor=world.actor, invitation_id=world.invitation_id, ip=_IP
        )
    return await platform_users.reinvite_org_admin(
        db.pool,
        actor=world.actor,
        org_id=ORG_ID,
        user_id=world.invited,
        email=_NEW_EMAIL,
        language="fr",
        public_url=PUBLIC_URL,
        ip=_IP,
    )


# ---------------------------------------------------------------------------
# 1. org_users.delete_org_user
# ---------------------------------------------------------------------------


class TestOrgUserDelete:
    """The Org Admin's deletion locks the target's chats first."""

    async def test_org_users_delete_locks_the_chats_once_before_the_users_delete_in_its_transaction(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """One ordered chat lock, on the delete's connection and committed transaction,
        before DELETE FROM users."""
        world = _org_world(db)

        await _delete(db, world.admin, world.target)

        lock = _one(locks).call
        delete = _one(db.matching(_USERS_DELETE_RE))
        assert delete.tx is not None
        assert (lock.via, lock.tx) == (delete.via, delete.tx)
        assert _position(db, lock) < _position(db, delete)
        assert db.transactions == [(delete.tx, "commit")]

    async def test_org_users_delete_locks_the_chats_after_the_guard_and_the_target_row(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """The last-admin guard, then the target's row lock, then the chat lock, then the
        users DELETE."""
        world = _org_world(db)

        await _delete(db, world.admin, world.target)

        guard = _one(db.matching(_GUARD_RE))
        target_lock = _one(
            [call for call in db.calls if call.normalized == norm(org_users._TARGET_SQL)]
        )
        lock = _one(locks).call
        delete = _one(db.matching(_USERS_DELETE_RE))
        assert (
            _position(db, guard)
            < _position(db, target_lock)
            < _position(db, lock)
            < _position(db, delete)
        )

    async def test_org_users_delete_lock_binds_the_org_and_the_target(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """WHERE org_id = <actor's org> AND owner_user_id = <target>, nothing else (no
        deletion-state filter: trashed chats are cascaded too)."""
        world = _org_world(db)

        await _delete(db, world.admin, world.target)

        assert _lock_predicates(_one(locks).call) == (
            {"org_id": ORG_ID, "owner_user_id": world.target},
            [],
        )

    async def test_org_users_delete_lock_selects_exactly_the_cascaded_chats(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """The lock selects the target's live and trashed chats in id order: exactly the
        chats the cascade deletes; no colleague's, no other org's."""
        world = _org_world(db)
        before = _chat_ids(db)

        await _delete(db, world.admin, world.target)

        cascaded = before - _chat_ids(db)
        assert cascaded == set(world.target_chats)
        assert _one(locks).chat_ids == sorted(world.target_chats)

    @pytest.mark.parametrize("case", _REFUSALS)
    async def test_org_users_delete_refused_issues_no_chat_lock_and_changes_nothing(
        self, db: FakeDb, locks: list[_Lock], case: str
    ) -> None:
        """The last active Org Admin (LastAdminError), an unknown, another org's or an
        invited user (UserNotInOrgError): no chat lock, nothing changes. A following
        valid deletion of a colleague then issues the one lock (bound to the colleague)."""
        world = _org_world(db)
        error: type[Exception] = accounts.UserNotInOrgError
        if case == "last-admin":
            target = world.admin_id
            error = accounts.LastAdminError
        elif case == "other-org":
            target = _member(db, org_id=OTHER_ORG_ID, role="org_admin")
            _chats_of(db, target)
        elif case == "invited":
            target = _invited(db, role="editor")
        else:
            target = uuid.uuid4()
        before = db.snapshot()

        with pytest.raises(error):
            await _delete(db, world.admin, target)

        assert db.snapshot() == before
        assert locks == []
        await _delete(db, world.admin, world.colleague)
        assert len(locks) == 1, locks
        assert _lock_predicates(locks[0].call)[0]["owner_user_id"] == world.colleague

    async def test_org_users_delete_user_without_chats_still_works(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """No chats: the lock selects nothing, the account goes, user.delete is recorded
        as before."""
        admin_id = _member(db, role="org_admin")
        target = _member(db)
        db.open_session(target)

        result = await _delete(db, _principal(db, admin_id), target)

        assert result is None
        assert target not in db.users
        row = _one(db.audit_rows())
        assert (row["action"], row["target_ids"], row["metadata"]) == (
            "user.delete",
            [str(target)],
            {"sessions_revoked": 1},
        )
        assert [lock.chat_ids for lock in locks] == [[]]

    async def test_org_users_delete_with_chats_keeps_cascades_audit_and_silence(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Unchanged behaviour: the target's chats and their messages (trashed included)
        go, every other chat stays as it was; one user.delete event with
        {"sessions_revoked": 2}; returns None; nothing is logged."""
        caplog.set_level(logging.DEBUG)
        world = _org_world(db)
        kept = _chat_state(db, world.kept_chats)

        result = await _delete(db, world.admin, world.target)

        assert result is None
        assert world.target not in db.users
        assert _gone(db, world.target_chats)
        assert _chat_state(db, world.kept_chats) == kept
        row = _one(db.audit_rows())
        assert (row["action"], row["actor_kind"], str(row["actor_user_id"])) == (
            "user.delete",
            "member",
            str(world.admin_id),
        )
        assert (str(row["org_id"]), row["target_type"], row["target_ids"]) == (
            str(ORG_ID),
            "user",
            [str(world.target)],
        )
        assert row["metadata"] == {"sessions_revoked": 2}
        assert _admino_records(caplog) == []

    async def test_org_users_delete_chat_lock_failure_rolls_everything_back(
        self, db: FakeDb
    ) -> None:
        """The chat lock fails: the error propagates, the transaction rolls back, nothing is
        deleted and nothing is audited."""
        world = _org_world(db)
        before = db.snapshot()
        db.fail_sql = _CHAT_LOCK_FAIL

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await _delete(db, world.admin, world.target)

        assert db.snapshot() == before
        assert db.audit_rows() == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:DeadlockDetectedError"]


# ---------------------------------------------------------------------------
# 2. organizations.purge_due_orgs (_purge_org)
# ---------------------------------------------------------------------------


class TestOrgPurge:
    """The purge locks the due org's chats first, before the org row."""

    async def test_organizations_purge_locks_the_chats_first_in_the_orgs_transaction(
        self, db: FakeDb, root: Path, locks: list[_Lock]
    ) -> None:
        """The chat lock is the first statement of the org's transaction, before the org
        row's FOR UPDATE re-check and DELETE FROM users; the transaction commits."""
        world = _purge_world(db)

        assert await _purge(db, root) == 1

        lock = _one(locks).call
        delete = _one(db.matching(_USERS_DELETE_RE))
        assert delete.tx is not None
        same_tx = _in_tx(db, delete)
        assert same_tx[0] is lock
        org_lock = _one([call for call in same_tx if _locks_the_org(call, world.org_id)])
        assert _position(db, lock) < _position(db, org_lock) < _position(db, delete)
        assert db.transactions == [(delete.tx, "commit")]

    async def test_organizations_purge_lock_binds_only_the_due_org(
        self, db: FakeDb, root: Path, locks: list[_Lock]
    ) -> None:
        """WHERE org_id = <the due org>, nothing else (every chat of the org, trashed
        included, whoever owns it)."""
        world = _purge_world(db)

        await _purge(db, root)

        assert _lock_predicates(_one(locks).call) == ({"org_id": world.org_id}, [])

    async def test_organizations_purge_lock_selects_exactly_the_cascaded_chats(
        self, db: FakeDb, root: Path, locks: list[_Lock]
    ) -> None:
        """Every chat of the due org (users of every status, live and trashed) in id
        order; no chat of an active or another org."""
        world = _purge_world(db)
        before = _chat_ids(db)

        await _purge(db, root)

        cascaded = before - _chat_ids(db)
        assert cascaded == set(world.org_chats)
        assert _one(locks).chat_ids == sorted(world.org_chats)

    @pytest.mark.parametrize("moment", _MOMENTS)
    async def test_organizations_purge_org_cancelled_concurrently_purges_nothing(
        self,
        db: FakeDb,
        root: Path,
        locks: list[_Lock],
        monkeypatch: pytest.MonkeyPatch,
        moment: str,
    ) -> None:
        """Cancelled after the due lookup or while the purge took the chat lock: the purge
        locked the org's chats first, then its locked re-check skips the org: 0 purged,
        no users DELETE, every chat and user kept, no org.purge event."""
        world = _purge_world(db)
        kept = _chat_state(db, world.org_chats)

        def cancel() -> None:
            db.add_org(world.org_id, status="deactivated")

        if moment == "after-due-lookup":
            db.after_org_lookup = cancel
        else:
            handle = db.handle

            def hook(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
                result = handle(method, sql, args, via, tx)
                if _CHAT_LOCK_RE.fullmatch(norm(sql)):
                    cancel()
                return result

            monkeypatch.setattr(db, "handle", hook)

        assert await _purge(db, root) == 0

        assert db.orgs[world.org_id]["status"] == "deactivated"
        assert set(world.users) <= set(db.users)
        assert _chat_state(db, world.org_chats) == kept
        assert db.audit_rows("org.purge") == []
        assert db.matching(_USERS_DELETE_RE) == []
        assert _lock_predicates(_one(locks).call)[0] == {"org_id": world.org_id}

    async def test_organizations_purge_org_without_chats_is_still_purged(
        self, db: FakeDb, root: Path, locks: list[_Lock]
    ) -> None:
        """No chats: the lock selects nothing; the org and its users go and org.purge is
        recorded with the same metadata as before."""
        world = _purge_world(db, with_chats=False)

        assert await _purge(db, root) == 1

        assert world.org_id not in db.orgs
        assert not set(world.users) & set(db.users)
        row = _one(db.audit_rows("org.purge"))
        assert row["metadata"] == {"users_purged": 4, "audit_events_purged": 0}
        assert [lock.chat_ids for lock in locks] == [[]]

    async def test_organizations_purge_with_chats_keeps_cascades_audit_and_silence(
        self, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Unchanged behaviour: the due org's chats and messages go, the other orgs' chats
        stay as they were; one org.purge event (system actor, target the org,
        {"users_purged": 4, "audit_events_purged": 0}); nothing is logged."""
        caplog.set_level(logging.DEBUG)
        world = _purge_world(db)
        kept = _chat_state(db, world.kept_chats)

        assert await _purge(db, root) == 1

        assert _gone(db, world.org_chats)
        assert _chat_state(db, world.kept_chats) == kept
        row = _one(db.audit_rows("org.purge"))
        assert (row["actor_kind"], row["org_id"], row["target_type"], row["target_ids"]) == (
            "system",
            None,
            "organization",
            [str(world.org_id)],
        )
        assert row["metadata"] == {"users_purged": 4, "audit_events_purged": 0}
        assert _admino_records(caplog) == []

    async def test_organizations_purge_chat_lock_failure_rolls_the_org_back(
        self, db: FakeDb, root: Path
    ) -> None:
        """The chat lock fails: that org's transaction rolls back, nothing is purged (it is
        retried at the next run)."""
        _purge_world(db)
        before = db.snapshot()
        db.fail_sql = _CHAT_LOCK_FAIL

        assert await _purge(db, root) == 0

        assert db.snapshot() == before
        assert [outcome for _, outcome in db.transactions] == ["rollback:DeadlockDetectedError"]


# ---------------------------------------------------------------------------
# 3. invitations.revoke_pending_invitation (revoke and Super Admin re-invite)
# ---------------------------------------------------------------------------


class TestInvitationRevoke:
    """Revoking an invitation locks that invited account's chats first."""

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_locks_the_chats_right_before_the_users_delete(
        self, db: FakeDb, locks: list[_Lock], entry: str
    ) -> None:
        """One chat lock on the delete's connection and committed transaction, the
        statement right before DELETE FROM users."""
        world = _revoke_world(db, entry)

        await _revoke(db, world)

        lock = _one(locks).call
        delete = _one(db.matching(_USERS_DELETE_RE))
        assert delete.tx is not None
        assert (lock.via, lock.tx) == (delete.via, delete.tx)
        same_tx = _in_tx(db, delete)
        assert same_tx[same_tx.index(delete) - 1] is lock
        assert db.transactions == [(delete.tx, "commit")]

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_lock_binds_the_invitation_and_the_org(
        self, db: FakeDb, locks: list[_Lock], entry: str
    ) -> None:
        """WHERE org_id = <the org> AND owner_user_id = (the user of that invitation while
        it is pending): binds exactly the invitation id and the org id."""
        world = _revoke_world(db, entry)

        await _revoke(db, world)

        lock = _one(locks).call
        bound, other = _lock_predicates(lock)
        assert bound == {"org_id": ORG_ID}
        owner = _OWNER_SUBQUERY_RE.fullmatch(_one(other))
        assert owner is not None, other
        sub_bound, sub_other = _predicates(owner["where"], lock.args)
        assert sub_bound == {"id": world.invitation_id}
        assert [re.sub(r"^\w+\.", "", atom) for atom in sub_other] == ["accepted_at is null"]
        assert sorted(plain(arg) for arg in lock.args) == sorted([world.invitation_id, ORG_ID])

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_lock_selects_exactly_the_cascaded_chats(
        self, db: FakeDb, locks: list[_Lock], entry: str
    ) -> None:
        """The invited account's chats (live and trashed) in id order: exactly what the
        cascade deletes; no colleague's, no other org's."""
        world = _revoke_world(db, entry, invited_chats=True)
        before = _chat_ids(db)

        await _revoke(db, world)

        cascaded = before - _chat_ids(db)
        assert cascaded == set(world.invited_chats)
        assert _one(locks).chat_ids == sorted(world.invited_chats)

    @pytest.mark.parametrize("case", _NOT_FOUND)
    async def test_invitations_revoke_not_found_locks_no_chat_and_changes_nothing(
        self, db: FakeDb, locks: list[_Lock], case: str
    ) -> None:
        """Another org's pending invitation (its account owns chats), an unknown id or an
        accepted invitation (its member owns chats): InvitationNotFoundError, nothing
        changes; the one chat lock selects no chat."""
        admin = _principal(db, _member(db, role="org_admin"))
        _chats_of(db, _member(db))
        if case == "other-org":
            other = _invited(db, org_id=OTHER_ORG_ID, role="editor")
            _chats_of(db, other)
            invitation_id = _invitation_id(db, other)
        elif case == "accepted":
            member = _member(db)
            db.add_invitation(member)
            invitation = db.invitation_of(member)
            assert invitation is not None
            invitation["accepted_at"] = datetime.now(UTC)
            _chats_of(db, member)
            invitation_id = plain(invitation["id"])
        else:
            invitation_id = uuid.uuid4()
        before = db.snapshot()

        with pytest.raises(invitations.InvitationNotFoundError):
            await invitations.revoke_invitation(
                db.pool, actor=admin, invitation_id=invitation_id, ip=_IP
            )

        assert db.snapshot() == before
        assert [lock.chat_ids for lock in locks] == [[]]

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_without_chats_still_works(
        self, db: FakeDb, locks: list[_Lock], entry: str
    ) -> None:
        """The usual case (an invited account has no chats): the lock selects nothing, the
        account and its invitation go, invitation.revoke is recorded as before."""
        world = _revoke_world(db, entry)

        await _revoke(db, world)

        assert world.invited not in db.users
        assert world.invitation_id not in db.invitations
        row = _one(db.audit_rows("invitation.revoke"))
        assert (row["target_type"], row["target_ids"], row["metadata"]) == (
            "invitation",
            [str(world.invitation_id)],
            {"user_id": str(world.invited)},
        )
        assert [lock.chat_ids for lock in locks] == [[]]

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_with_chats_keeps_cascades_audit_and_silence(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture, entry: str
    ) -> None:
        """Unchanged behaviour: the invited account's chats and messages go, every other
        chat stays as it was; the same audit events (revoke; create for the
        replacement) with the same metadata; nothing is logged."""
        caplog.set_level(logging.DEBUG)
        world = _revoke_world(db, entry, invited_chats=True)
        kept = _chat_state(db, world.kept_chats)

        await _revoke(db, world)

        assert world.invited not in db.users
        assert _gone(db, world.invited_chats)
        assert _chat_state(db, world.kept_chats) == kept
        expected = ["invitation.revoke"]
        if entry == "super-admin-replace":
            expected.append("invitation.create")
        assert [row["action"] for row in db.audit_rows()] == expected
        row = db.audit_rows("invitation.revoke")[0]
        assert (row["actor_kind"], str(row["actor_user_id"]), str(row["org_id"])) == (
            world.actor.kind,
            str(world.actor.user_id),
            str(ORG_ID),
        )
        assert row["metadata"] == {"user_id": str(world.invited)}
        assert _admino_records(caplog) == []

    @pytest.mark.parametrize("entry", _ENTRIES)
    async def test_invitations_revoke_chat_lock_failure_rolls_everything_back(
        self, db: FakeDb, entry: str
    ) -> None:
        """The chat lock fails: the error propagates, nothing is deleted, sent or
        audited."""
        world = _revoke_world(db, entry)
        before = db.snapshot()
        db.fail_sql = _CHAT_LOCK_FAIL

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await _revoke(db, world)

        assert db.snapshot() == before
        assert [outcome for _, outcome in db.transactions] == ["rollback:DeadlockDetectedError"]


# ---------------------------------------------------------------------------
# 4. A deletion next to the org-wide notice (sequential composition)
# ---------------------------------------------------------------------------


class TestDeleteAndNotice:
    """A deletion and the notice both complete; every remaining live chat of the org
    holds the notice exactly once; both lock the chats in the same order."""

    def _deletion_lock(self, db: FakeDb, locks: list[_Lock]) -> _Lock:
        delete = _one(db.matching(_USERS_DELETE_RE))
        return _one(
            [lock for lock in locks if (lock.call.via, lock.call.tx) == (delete.via, delete.tx)]
        )

    def _assert_one_notice_per_remaining_live_chat(self, db: FakeDb, world: _OrgWorld) -> None:
        counts = {chat_id: _notices(db, chat_id) for chat_id in world.kept_chats}
        expected = {chat_id: int(chat_id in world.org_live) for chat_id in world.kept_chats}
        assert counts == expected
        assert _gone(db, world.target_chats)

    async def test_chats_notice_after_a_deletion_reaches_every_remaining_live_chat_once(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """Delete a user with two live chats, then the notice: the remaining live chats of
        the org each get it once; trashed and other-org chats none; the deleted
        user's chats are gone. The deletion locked its chats in id order."""
        world = _org_world(db)

        await _delete(db, world.admin, world.target)
        count = await chats.append_org_notice(
            db.pool, TenantContext.from_principal(world.admin), _NOTICE
        )

        assert count == len(world.org_live)
        self._assert_one_notice_per_remaining_live_chat(db, world)
        deletion = self._deletion_lock(db, locks)
        assert deletion.chat_ids == sorted(world.target_chats)

    async def test_chats_notice_before_a_deletion_leaves_one_notice_per_remaining_live_chat(
        self, db: FakeDb, locks: list[_Lock]
    ) -> None:
        """The notice first (every live chat of the org, the target's included), then the
        deletion: the remaining live chats still hold exactly one notice each. The
        chats both locked come in the same order in both locks."""
        world = _org_world(db)

        count = await chats.append_org_notice(
            db.pool, TenantContext.from_principal(world.admin), _NOTICE
        )
        await _delete(db, world.admin, world.target)

        assert count == len(world.org_live) + len(world.target_live)
        self._assert_one_notice_per_remaining_live_chat(db, world)
        deletion = self._deletion_lock(db, locks)
        notice = _one([lock for lock in locks if lock is not deletion])
        shared = set(notice.chat_ids) & set(deletion.chat_ids)
        assert shared == set(world.target_live)
        assert [chat_id for chat_id in notice.chat_ids if chat_id in shared] == [
            chat_id for chat_id in deletion.chat_ids if chat_id in shared
        ]
