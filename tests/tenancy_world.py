"""Shared world and route catalog of the tenant isolation suite (GH-163).

The suite (``tests/test_tenancy.py``, ``tests/test_tenancy_cross_org.py`` and
``tests/test_tenancy_memory.py``) runs the FastAPI app from ``create_app()``
against the in-memory database of tests/db_fakes.py, with real session cookies
resolved by the real ``server.require_session``.

Inputs: a ``FakeDb``. Outputs:
- ``build_world(db)``: two active organizations (A = ``ORG_ID``, B =
  ``OTHER_ORG_ID``), each with an Org Admin and an Editor, plus a Super
  Admin; every account has a live session and the password ``PASSWORD``.
  Both orgs have data residency off, the default tool permission matrix and
  an org_settings row; the platform settings row exists.
- ``make_app(agent)`` / ``make_client(app)``: the app and a TestClient.
- ``seed_chat`` / ``seed_pending_confirmation`` / ``chat_runtime_state``: a
  persisted chat of an account, a pending confirmation of it in the server's
  chat runtime, and what that runtime holds (GH-176).
- The catalog: ``ROUTES`` (every registered API route, classified),
  ``ROLE_MATRIX`` (#139 §2.1, written from the tracker, never from
  ``access.py``), ``PENDING_CAPABILITIES`` (capabilities without a route yet,
  with the issue that adds it), ``SERVICE_CAPABILITIES`` (capabilities a
  routed service checks in addition to its route's capability, with those
  routes) and ``PROJECT_ROLES`` (#139 §2.2, pending until project routes
  exist).

Adding a route: give it a ``RouteSpec`` row in ``ROUTES`` and its cases in the
suite. The completeness tests in tests/test_tenancy.py fail for a registered
route without a row, and for a capability that is neither routed nor pending.
A capability moves from ``PENDING_CAPABILITIES`` to the row of its first
route, or to ``SERVICE_CAPABILITIES`` when it gates part of an existing
route's service (GH-169: ``org.instructions.manage``, checked by the org
settings service behind GET/PATCH /api/org/settings). A service capability
must have exactly its routes' roles in ``ROLE_MATRIX``, so the role cases of
those routes cover it.
GH-167's two capabilities (``platform.org_metadata.view``,
``platform.users.manage``) are named by value through ``_capability`` so the
catalog imports before access.py defines them (see its docstring).

GH-176 (persisted, owner-private chats): the six chat routes (POST and GET
/api/chats, GET/PATCH/DELETE /api/chats/{chat_id}, POST
/api/chats/{chat_id}/messages) are member rows gated by ``chat.send`` (Org
Admin, Editor; the Super Admin gets 403). Not found, another
org's and another user's chat all answer ``CHAT_NOT_FOUND``. Chats live in the
FakeDb's ``chats`` / ``chat_messages`` tables (so ``db.snapshot()`` holds
them); the only in-memory chat state is ``server._chat_runtime`` (per-chat
locks and pending confirmations). Helpers: ``seed_chat`` (a live chat of an
account, with messages), ``seed_pending_confirmation`` (a live pending
confirmation of a chat in the runtime) and ``chat_runtime_state`` (what the
runtime holds for the stored chats, for "nothing changed" snapshots).

GH-187 (attachments): ``POST /api/chats/{chat_id}/attachments`` is a member row
gated by ``file.upload`` (moved out of ``PENDING_CAPABILITIES``): one file as
the raw request body, its name percent-encoded in ``X-Attachment-Name``; only
the chat's owner uploads, so another org's, a colleague's and an unknown chat
answer ``CHAT_NOT_FOUND``. ``GET /api/attachments/{attachment_id}`` (metadata)
and ``GET /api/attachments/{attachment_id}/content`` (download) are member rows
gated by ``chat.send``: only the chat's owner reads, anything else answers
``ATTACHMENT_NOT_FOUND``. Helpers: ``use_attachment_storage`` points
``organizations.ATTACHMENTS_ROOT`` (read at call time through
``attachments.attachments_root()``) at a test directory and gives orgs A and B
a storage quota (``add_org`` leaves 0: every upload refused);
``upload_headers`` / ``UPLOAD_BODY`` are a valid upload (a short UTF-8 text
file); ``seed_attachment`` stores an attachment row of a chat and its file
under the root; ``attachment_files`` maps every file under the root to its
bytes, for "nothing changed on disk" checks.

GH-190 (context budgeting and attachment exclusion): ``PATCH
/api/attachments/{attachment_id}`` (``{"active": bool}``: exclude a file from
later turns, or include it again) and ``GET /api/chats/{chat_id}/attachments``
(the chat's files, paged) are member rows gated by ``chat.send``. Only the
owner reaches them: anything but the caller's own live attachment is
``ATTACHMENT_NOT_FOUND``, anything but the caller's own live chat
``CHAT_NOT_FOUND``. ``seed_attachment`` passes ``active=False`` (an excluded
file, migration 0030) through to ``db.add_attachment`` with the other fields.

GH-194 (the trash): seven member rows gated by ``chat.send`` (Org Admin,
Editor; the Super Admin gets 403). ``GET /api/trash`` (the
caller's own trash, paged) and ``DELETE /api/trash`` (empty it) are
``own_user``; ``POST /api/trash/chats/{chat_id}/restore``, ``POST
/api/trash/attachments/{attachment_id}/restore``, ``DELETE
/api/trash/chats/{chat_id}`` and ``DELETE /api/trash/attachments/{attachment_id}``
(restore, delete forever) and ``DELETE /api/attachments/{attachment_id}``
(move one live file to the trash) are ``path_id``. The trash is the owner's
own (Decision 1, V1): another org's, a colleague's (an Org Admin's request on
an Editor's item included) and an unknown item answer ``CHAT_NOT_FOUND`` or
``ATTACHMENT_NOT_FOUND`` and change nothing. ``DELETE /api/chats/{chat_id}``
keeps its row (it now goes through the trash service). Helpers:
``seed_trashed_chat`` (a chat of an account deleted ``TRASHED_AGO`` ago, well
inside the default 30-day retention, with its messages and the files its
deletion moved) and ``seed_trashed_attachment`` (a file deleted on its own in
a live chat, or with its trashed chat), both through ``FakeDb.add_chat`` /
``add_attachment`` with ``deleted_at`` (the FakeDb gives the trash group of
migration 0032's backfill once 0032 ships); each trashed file has its
original and a derived text file ``<id>.d/text.txt`` under the attachments
root, so ``attachment_files`` sees what a purge would remove.

GH-245 (retry a failed answer): ``POST /api/chats/{chat_id}/retry`` (no body) is a
member row gated by ``chat.send``: only the chat's owner re-runs its failed last
turn, so another org's, a colleague's and an unknown chat answer
``CHAT_NOT_FOUND``. ``seed_failed_chat`` stores a chat whose one turn failed (the
question, then the answer stored ``error`` or ``stopped``, as the server stores a
failed run's last message): the state a retry acts on.

GH-306 (the read-only member role retired): #139 §2.1 has three columns, the
Super Admin, the Org Admin and the Editor, so ``Role`` / ``MEMBER_ROLES`` and
``ROLE_MATRIX`` hold those three and every org of the world has exactly an
Org Admin and an Editor. A capability of every member (``_MEMBERS``) stays
with Org Admins and Editors. The project roles of §2.2 (``PROJECT_ROLES``) are
a separate, pending catalog and don't change.

Security notes:
- Passwords, tokens and emails here are fixed fake values, never secrets.
- The expected role matrix is spelled out here on purpose: deriving it from
  ``access.can`` would make the HTTP role tests agree with any mistake there.
"""

from __future__ import annotations

import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal, cast
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from admino import organizations, server
from admino.access import Capability
from admino.config import AppConfig
from admino.models import AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, fake_hash

if TYPE_CHECKING:
    from collections.abc import Sequence

    import pytest
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

Role = Literal["super_admin", "org_admin", "editor"]
MemberRole = Literal["org_admin", "editor"]

ROLES: Final[tuple[Role, ...]] = ("super_admin", "org_admin", "editor")
MEMBER_ROLES: Final[tuple[MemberRole, ...]] = ("org_admin", "editor")

SESSION_COOKIE: Final = "admino_session"
PASSWORD: Final = "tenancy-Suite-163-quartz"
# The valid new password of the suite's POST /api/me/password requests (GH-166).
NEW_PASSWORD: Final = "tenancy-Changed-166-meadow"
CLIENT_IP: Final = "203.0.113.163"
FORBIDDEN: Final = {"detail": "Forbidden"}
UNAUTHORIZED: Final = {"detail": "Unauthorized"}
# GH-176: unknown, another org's, another user's (and a trashed) chat: one answer.
CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
# GH-187: anything but the caller's own live attachment (another org's, a colleague's,
# a trashed chat's, an unknown id, a row whose file is missing): one answer.
ATTACHMENT_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
# GH-187: the storage quota use_attachment_storage gives orgs A and B (64 MiB).
ATTACHMENT_QUOTA: Final = 64 * 1024 * 1024
# GH-187: a valid upload, a short UTF-8 text file (detected as txt from its content).
UPLOAD_NAME: Final = "tenancy-notes-187.txt"
UPLOAD_BODY: Final = b"Tenancy upload 187: notes of the meeting.\n"


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
        """All five accounts: the Super Admin, then org A's and org B's members."""
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
# Chats (GH-176): persisted rows, and the in-memory runtime's pending confirmations
# ---------------------------------------------------------------------------


def _user_id(owner: Account | uuid.UUID) -> uuid.UUID:
    """An account's user id (or the id itself)."""
    return owner.user_id if isinstance(owner, Account) else owner


def seed_chat(
    db: FakeDb,
    owner: Account | uuid.UUID,
    *,
    title: str = "",
    messages: Sequence[tuple[str, str]] = (),
    legacy_session_id: str | None = None,
    external_content: bool = False,
) -> uuid.UUID:
    """Store a live chat of ``owner`` (an account or a user id) in the owner's org, with
    ``messages``; its id.

    ``messages`` are (role, content) pairs stored in order (``complete``). A
    title makes ``title_source`` "user"; none leaves "" and "auto". A
    ``legacy_session_id`` makes it the owner's chat of that legacy session id.
    """
    chat_id = db.add_chat(
        _user_id(owner),
        title=title,
        title_source="user" if title else "auto",
        legacy_session_id=legacy_session_id,
        external_content=external_content,
    )
    for role, content in messages:
        db.add_chat_message(chat_id, role, content)
    return chat_id


def seed_failed_chat(
    db: FakeDb,
    owner: Account | uuid.UUID,
    *,
    title: str,
    question: str,
    answer: str,
    status: str = "error",
) -> uuid.UUID:
    """GH-245: store a live, titled chat of ``owner`` whose one turn failed; its id.

    ``question`` is the user message (``complete``), ``answer`` the assistant reply
    stored with ``status`` (``error`` or ``stopped``), the way the server stores a
    failed run's last message. The chat's latest message is the failed answer, so a
    retry by the owner passes the status check. A title (``title_source`` "user")
    keeps the first-exchange title rule out of the request.
    """
    chat_id = seed_chat(db, owner, title=title)
    db.add_chat_message(chat_id, "user", question)
    db.add_chat_message(chat_id, "assistant", answer, status=status)
    return chat_id


def seed_pending_confirmation(
    owner: Account | uuid.UUID, chat_id: uuid.UUID, confirmation_id: str
) -> PendingConfirmation:
    """Store a live (5 minutes) google_calendar.create confirmation of the chat in
    ``server._chat_runtime`` (read at call time: it exists from GH-176); return it.

    Call it after ``make_app``: ``create_app()`` clears the runtime (a restart).
    """
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=str(chat_id),
        tool_call=ToolCall(tool="google_calendar", action="create", args={}),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    server._chat_runtime.set_pending(chat_id, _user_id(owner), pending)
    return pending


def chat_runtime_state(db: FakeDb) -> dict[str, Any] | None:
    """What ``server._chat_runtime`` holds: its entry count and, for every stored chat,
    its pending confirmation (as JSON values) or None.

    None while the server has no runtime (before GH-176), so the "nothing changed"
    snapshots of unrelated routes stay meaningful; tests/test_tenancy_roles.py pins
    that the runtime exists and is the only in-memory chat state.
    """
    runtime = getattr(server, "_chat_runtime", None)
    if runtime is None:
        return None
    pending: dict[str, Any] = {}
    for chat_id in db.chats:
        found = runtime.get_pending(uuid.UUID(str(chat_id)))
        pending[str(chat_id)] = None if found is None else found.model_dump(mode="json")
    return {"entries": len(runtime), "pending": pending}


# ---------------------------------------------------------------------------
# Attachments (GH-187): the storage root, a valid upload, seeded files
# ---------------------------------------------------------------------------


def use_attachment_storage(monkeypatch: pytest.MonkeyPatch, world: World, root: Path) -> Path:
    """Point ``organizations.ATTACHMENTS_ROOT`` at ``root`` (created, empty) and give
    orgs A and B a storage quota of ``ATTACHMENT_QUOTA``; return ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
    for org_id in (world.org_a, world.org_b):
        world.db.add_org(org_id, storage_quota_bytes=ATTACHMENT_QUOTA)
    return root


def upload_headers(name: str = UPLOAD_NAME) -> dict[str, str]:
    """The upload's ``X-Attachment-Name`` header: ``name`` percent-encoded (UTF-8).

    The client adds ``Content-Length`` for a bytes body; the declared
    ``Content-Type`` is ignored by the route.
    """
    return {"X-Attachment-Name": urllib.parse.quote(name, safe="")}


def seed_attachment(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    filename: str = "tenancy-file-187.txt",
    data: bytes = b"Tenancy attachment 187\n",
    kind: str = "txt",
    **fields: Any,
) -> uuid.UUID:
    """Store an attachments row of ``chat_id`` (its owner's and org's) with ``filename``,
    ``kind`` and ``size_bytes = len(data)``, and write ``data`` to its file
    ``<ATTACHMENTS_ROOT>/<org_id>/<attachment_id>``; return the attachment's id.

    ``fields`` go to ``db.add_attachment`` (status, failure_reason, message_id,
    deleted_at, GH-190's active, ...). The root is read at call time: call
    ``use_attachment_storage`` first.
    """
    attachment_id = db.add_attachment(
        chat_id, filename=filename, kind=kind, size_bytes=len(data), **fields
    )
    chat = db.chat_row(chat_id)
    assert chat is not None
    directory = Path(organizations.ATTACHMENTS_ROOT) / str(chat["org_id"])
    directory.mkdir(parents=True, exist_ok=True)
    (directory / str(attachment_id)).write_bytes(data)
    return attachment_id


# GH-194: how long ago a seeded trash item was deleted (inside the default 30-day retention).
TRASHED_AGO: Final = timedelta(hours=1)


def seed_trashed_attachment(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    filename: str = "tenancy-trashed-194.txt",
    data: bytes = b"Tenancy trashed attachment 194\n",
    deleted_at: datetime | None = None,
    **fields: Any,
) -> uuid.UUID:
    """Store a trashed attachments row of ``chat_id`` (``seed_attachment`` with
    ``deleted_at``, ``TRASHED_AGO`` ago by default) and its derived text file
    ``<ATTACHMENTS_ROOT>/<org_id>/<attachment_id>.d/text.txt``; return its id.

    In a live chat the file was deleted on its own (its own trash group once
    migration 0032 ships: a trash item); in a trashed chat it went with the
    chat (the chat's group: not an item of its own). Call
    ``use_attachment_storage`` first.
    """
    stamp = deleted_at if deleted_at is not None else datetime.now(UTC) - TRASHED_AGO
    attachment_id = seed_attachment(
        db, chat_id, filename=filename, data=data, deleted_at=stamp, **fields
    )
    chat = db.chat_row(chat_id)
    assert chat is not None
    derived = Path(organizations.ATTACHMENTS_ROOT) / str(chat["org_id"]) / f"{attachment_id}.d"
    derived.mkdir(parents=True, exist_ok=True)
    (derived / "text.txt").write_bytes(data)
    return attachment_id


def seed_trashed_chat(
    db: FakeDb,
    owner: Account | uuid.UUID,
    *,
    title: str = "",
    messages: Sequence[tuple[str, str]] = (),
    filenames: Sequence[str] = (),
    deleted_at: datetime | None = None,
) -> uuid.UUID:
    """Store a chat of ``owner`` in the owner's org, moved to the trash ``TRASHED_AGO``
    ago (or at ``deleted_at``), with ``messages`` and one attachment per name in
    ``filenames`` trashed with it (same ``deleted_at``; ``seed_trashed_attachment``);
    return the chat's id.

    The chat is its own trash group once migration 0032 ships (a trash item); its
    files carry the chat's group (they come back with it). A title makes
    ``title_source`` "user".
    """
    stamp = deleted_at if deleted_at is not None else datetime.now(UTC) - TRASHED_AGO
    chat_id = db.add_chat(
        _user_id(owner),
        title=title,
        title_source="user" if title else "auto",
        deleted_at=stamp,
    )
    for role, content in messages:
        db.add_chat_message(chat_id, role, content)
    for name in filenames:
        seed_trashed_attachment(db, chat_id, filename=name, data=name.encode(), deleted_at=stamp)
    return chat_id


def attachment_files() -> dict[str, bytes]:
    """Every file under ``organizations.ATTACHMENTS_ROOT`` (read at call time): its path
    relative to the root (POSIX) -> its bytes. Empty when the root doesn't exist."""
    root = Path(organizations.ATTACHMENTS_ROOT)
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


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
_MEMBERS: Final[frozenset[Role]] = frozenset({"org_admin", "editor"})
_ALL: Final[frozenset[Role]] = frozenset(ROLES)


def _capability(value: str) -> Capability:
    """The Capability member with ``value``, or the bare value while access.py lacks it.

    A StrEnum member equals and hashes as its value, so every lookup by member
    (``ROLE_MATRIX[Capability.X]``, ``capability in routed``) works either way.
    Until the member exists, the completeness tests (``ROLE_MATRIX`` against
    ``Capability``) fail on the unknown value instead of the whole suite
    failing to import.
    """
    try:
        return Capability(value)
    except ValueError:
        return cast("Capability", value)


# GH-167: an org's users list and metadata; deactivate, reactivate, password
# reset and re-invite of an org's users.
_PLATFORM_ORG_METADATA_VIEW: Final = _capability("platform.org_metadata.view")
_PLATFORM_USERS_MANAGE: Final = _capability("platform.users.manage")

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
        # Super Admin user administration and org metadata (GH-167)
        _PLATFORM_ORG_METADATA_VIEW: _SA,
        _PLATFORM_USERS_MANAGE: _SA,
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
# issue moves its capability from here into a ROUTES row with HTTP cases (or
# into SERVICE_CAPABILITIES when an existing route's service checks it).
PENDING_CAPABILITIES: Final[MappingProxyType[Capability, str]] = MappingProxyType(
    {
        Capability.PLATFORM_REGISTRY_MANAGE: "#173",
        Capability.USAGE_VIEW_PLATFORM: "#183",
        Capability.AUDIT_VIEW_PLATFORM: "#171",
        Capability.ORG_MODELS_MANAGE: "#173",
        Capability.TEMPLATE_ORG_MANAGE: "#205",
        Capability.ORG_LETTERHEAD_MANAGE: "#207",
        Capability.USAGE_VIEW_ORG: "#183",
        Capability.AUDIT_VIEW_ORG: "#171",
        Capability.PROJECT_OPEN_ANY: "#185",
        Capability.PROJECT_CREATE: "#185",
        Capability.PROJECT_PERSONAL_DEFAULT: "#185",
        Capability.TEMPLATE_PERSONAL_MANAGE: "#205",
        Capability.PROJECT_READ_SHARED: "#197",
        Capability.EXPORT_CREATE: "#206",
        Capability.USAGE_VIEW_OWN: "#183",
    }
)

# Capabilities a routed service checks in addition to its route's capability,
# and the routes whose service checks them. No route of their own: the role
# cases of these routes cover them, so their ROLE_MATRIX roles equal the route
# capability's (tests/test_tenancy.py checks it). GH-169: the org settings
# service carries the org instructions in every response, so both GET and
# PATCH /api/org/settings require ``org.instructions.manage`` too.
SERVICE_CAPABILITIES: Final[MappingProxyType[Capability, tuple[tuple[str, str], ...]]] = (
    MappingProxyType(
        {
            Capability.ORG_INSTRUCTIONS_MANAGE: (
                ("GET", "/api/org/settings"),
                ("PATCH", "/api/org/settings"),
            ),
        }
    )
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
    # GH-166: the caller's own profile, languages, timezone, instructions and password.
    RouteSpec("GET", "/api/me", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    RouteSpec("PATCH", "/api/me", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    RouteSpec("POST", "/api/me/password", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    # --- org users and invitations ---
    RouteSpec("GET", "/api/org/users", "member", Capability.ORG_USERS_VIEW, "own_org"),
    RouteSpec(
        "PATCH",
        "/api/org/users/{user_id}",
        "member",
        Capability.ORG_USERS_ROLE_CHANGE,
        "path_id",
    ),
    RouteSpec(
        "POST",
        "/api/org/users/{user_id}/deactivate",
        "member",
        Capability.ORG_USERS_MANAGE,
        "path_id",
    ),
    RouteSpec(
        "POST",
        "/api/org/users/{user_id}/reactivate",
        "member",
        Capability.ORG_USERS_MANAGE,
        "path_id",
    ),
    RouteSpec(
        "DELETE",
        "/api/org/users/{user_id}",
        "member",
        Capability.ORG_USERS_MANAGE,
        "path_id",
    ),
    RouteSpec(
        "POST",
        "/api/org/users/{user_id}/password-reset",
        "member",
        Capability.ORG_USERS_MANAGE,
        "path_id",
    ),
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
    RouteSpec("POST", "/api/confirm/{confirmation_id}", "member", Capability.CHAT_SEND, "path_id"),
    # GH-176: persisted chats, private to their owner (not even an Org Admin reads them).
    RouteSpec("POST", "/api/chats", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec("GET", "/api/chats", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec("GET", "/api/chats/{chat_id}", "member", Capability.CHAT_SEND, "path_id"),
    RouteSpec("PATCH", "/api/chats/{chat_id}", "member", Capability.CHAT_SEND, "path_id"),
    RouteSpec("DELETE", "/api/chats/{chat_id}", "member", Capability.CHAT_SEND, "path_id"),
    RouteSpec("POST", "/api/chats/{chat_id}/messages", "member", Capability.CHAT_SEND, "path_id"),
    # GH-8: stop the chat's streamed run.
    RouteSpec("POST", "/api/chats/{chat_id}/stop", "member", Capability.CHAT_SEND, "path_id"),
    # GH-245: re-run the chat's failed last turn (the owner only, like a send).
    RouteSpec("POST", "/api/chats/{chat_id}/retry", "member", Capability.CHAT_SEND, "path_id"),
    # GH-187: upload a file into a chat of the caller's own; read an attachment's metadata
    # and download it (the chat's owner only).
    RouteSpec(
        "POST", "/api/chats/{chat_id}/attachments", "member", Capability.FILE_UPLOAD, "path_id"
    ),
    RouteSpec("GET", "/api/attachments/{attachment_id}", "member", Capability.CHAT_SEND, "path_id"),
    RouteSpec(
        "GET",
        "/api/attachments/{attachment_id}/content",
        "member",
        Capability.CHAT_SEND,
        "path_id",
    ),
    # GH-190: exclude or include an attachment of the caller's own; list a chat's files.
    RouteSpec(
        "PATCH", "/api/attachments/{attachment_id}", "member", Capability.CHAT_SEND, "path_id"
    ),
    RouteSpec("GET", "/api/chats/{chat_id}/attachments", "member", Capability.CHAT_SEND, "path_id"),
    # GH-194: move one live file to the trash; the caller's own trash (list, empty), and
    # restore and delete forever per item (owner-private, V1: not even an Org Admin).
    RouteSpec(
        "DELETE", "/api/attachments/{attachment_id}", "member", Capability.CHAT_SEND, "path_id"
    ),
    RouteSpec("GET", "/api/trash", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec("DELETE", "/api/trash", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec(
        "POST", "/api/trash/chats/{chat_id}/restore", "member", Capability.CHAT_SEND, "path_id"
    ),
    RouteSpec(
        "POST",
        "/api/trash/attachments/{attachment_id}/restore",
        "member",
        Capability.CHAT_SEND,
        "path_id",
    ),
    RouteSpec("DELETE", "/api/trash/chats/{chat_id}", "member", Capability.CHAT_SEND, "path_id"),
    RouteSpec(
        "DELETE",
        "/api/trash/attachments/{attachment_id}",
        "member",
        Capability.CHAT_SEND,
        "path_id",
    ),
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
    # GH-167: an org's accounts and metadata, and the Super Admin's user actions.
    RouteSpec(
        "GET",
        "/api/platform/orgs/{org_id}/users",
        "platform",
        _PLATFORM_ORG_METADATA_VIEW,
        "none",
    ),
    RouteSpec(
        "GET",
        "/api/platform/orgs/{org_id}/metadata",
        "platform",
        _PLATFORM_ORG_METADATA_VIEW,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/users/{user_id}/deactivate",
        "platform",
        _PLATFORM_USERS_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/users/{user_id}/reactivate",
        "platform",
        _PLATFORM_USERS_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/users/{user_id}/password-reset",
        "platform",
        _PLATFORM_USERS_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/users/{user_id}/invitation",
        "platform",
        _PLATFORM_USERS_MANAGE,
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
