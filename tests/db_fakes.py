"""Shared in-memory database for the service and HTTP tests (GH-151, GH-152, GH-153).

``FakeDb`` stands in for the users, organizations, invitations, sessions,
password_reset_tokens, email_outbox and audit_events tables behind a
pool-shaped object (``FakeDb.pool``). The real ``admino.auth``,
``admino.sessions``, ``admino.session_management``, ``admino.password_reset``,
``admino.invitations``, ``admino.email_outbox`` and ``admino.audit_events``
code runs against it: each statement is recognised by its table and verb, and
its bind parameters are applied to the in-memory tables, so a test can log in,
list and revoke sessions, request and confirm a password reset, send, list,
revoke, resend and accept invitations, and check the result.

Inputs: organizations, accounts and sessions added with ``add_org`` /
``add_account`` / ``open_session``.
Outputs: the recorded calls (``calls``: method, SQL, args, which pool or
connection ran it and inside which transaction), the table state, and the
outcome of every transaction (``transactions``: commit or rollback).

Organizations and invitations (GH-153):
- ``orgs`` holds the organizations rows (id, name, seats, status, ...).
  ``add_org`` creates or updates one; ``add_account`` creates a member's org
  (active, 100 seats) when it doesn't exist yet. An account's ``org_status``
  (``add_account(org_status=...)``, or set on ``users[id]`` later) is a
  per-account view of the org's status, kept for the login, session and reset
  lookups written before the organizations table existed; None (the default)
  follows the org's row.
- ``invitations`` holds the invitations rows of migration 0010 (id, user_id,
  token_hash, created_at, sent_at, expires_at, accepted_at), keyed by id.
- Every statement that names ``invitations`` or reads ``organizations`` as
  its main table, every INSERT, UPDATE and DELETE on ``users``, and every
  users SELECT scoped by ``org_id = $n`` alone runs through a small SQL reader
  (``_Statement``). It applies exactly what the SQL states: the FROM / JOIN
  (inner and LEFT) / USING / UPDATE ... FROM sources, their ON conditions, the
  AND-ed WHERE predicates (``=``, ``<>``, ``<``, ``<=``, ``>``, ``>=`` between
  columns, bind parameters, literals and ``now()``; ``IS [NOT] NULL``;
  ``[NOT] IN (...)`` with a list or an uncorrelated SELECT), ``EXISTS
  (SELECT ...)`` as the whole query, ``count(...)``, ``ORDER BY``, ``LIMIT``,
  ``FOR UPDATE`` (recorded, no effect) and ``RETURNING``. A predicate the SQL
  doesn't state isn't applied, so a missing org scope, status or expiry
  filter shows up in the results. Values: ``$n`` (optionally cast), string and
  integer literals, ``NULL``, ``now()`` and ``now() + $n::interval`` (the bound
  value must be a timedelta).
- The reader fails the calling test with an AssertionError for anything else
  (OR, BETWEEN, CTEs, correlated subqueries, ON CONFLICT, another table in a
  join, ...): an unrecognised statement on these tables never silently
  returns None, [] or "OK".
- Like PostgreSQL, an unknown column raises UndefinedColumnError, an
  unqualified column two sources share raises AmbiguousColumnError, and the
  schema's rules raise the driver's errors: the case-insensitive unique email
  (UniqueViolationError, whose text repeats the email, as the driver's does),
  the users CHECKs of migration 0004 (for the columns a statement writes) and
  its kind/org_id immutability trigger, the invitations CHECKs of migration
  0010 (a 32-byte token hash, ``sent_at >= created_at``, ``sent_at < expires_at
  <= sent_at + 72 hours``), UNIQUE user_id and token_hash, NOT NULL
  expires_at, and the foreign keys. Deleting a users row cascades to its
  invitation, queued emails, sessions and reset token.
- ``now()`` is the fake's clock (``datetime.now(UTC)``) when the statement
  runs; ``created_at`` and ``sent_at`` default to it.
- ``after_invitation_lookup`` runs once, right after the first SELECT on
  invitations bound to a token hash (a concurrent accept, revoke, rotation or
  expiry between the lookup and the transaction).

The sessions table is the schema after migration 0009 (GH-152):
- Each row stores its own ``idle_timeout_minutes`` (15 to 480, NOT NULL, no
  default: an INSERT without it fails like PostgreSQL's NotNullViolationError)
  and its ``expires_at`` (at most 72 hours after ``created_at``); both CHECKs
  are enforced (CheckViolationError).
- There is no ``revoked_at`` column: revoking a session deletes its row. Any
  statement that names ``revoked_at`` fails with asyncpg's
  UndefinedColumnError, as it would against the migrated database.
- ``created_at`` and ``last_seen_at`` default to the fake's now.

Semantics the tests rely on:
- ``pool.acquire()`` yields a new connection; ``conn.transaction()`` snapshots
  the tables and restores them when the block raises (a rollback), so a
  failure inside a transaction leaves nothing behind, as in PostgreSQL. The
  pool itself has no ``transaction()`` (asyncpg's Pool hasn't either).
- The session statements apply the predicates their SQL names: the list query
  keeps only live sessions when it says ``expires_at > now()`` and
  ``last_seen_at + make_interval(mins => idle_timeout_minutes) > now()``, the
  purge deletes what its ``<= now()`` predicates name, and the users lookup of
  a forced logout applies its ``org_id = $n`` and ``deleted_at IS NULL``
  filters. A predicate the SQL doesn't state isn't applied, so the HTTP tests
  observe what the real query would return.
- The reset-token upsert keeps one row per user (ON CONFLICT (user_id)) and
  returns its ``expires_at`` (now + 30 minutes); the SQL's own lifetime is
  pinned by a dedicated test, not by this fake.
- ``fail_audit`` makes every INSERT INTO audit_events fail like a driver
  error; ``after_token_lookup`` runs right after the reset-token lookup (a
  concurrent request, confirm or expiry between the lookup and the consume).
- Queued emails record the recipient's ``language`` (copied from the users
  row, as the real INSERT ... SELECT does).
- Rows are returned with asyncpg's own UUID type, and INET values as
  ``ipaddress`` objects, as the driver does.

Security notes:
- Test infrastructure only: no real PostgreSQL, no network.
- Tokens here are generated per test with ``secrets``; nothing is a real secret.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, Final

import asyncpg
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

ORG_ID: Final = uuid.UUID("d4e5f6a7-b8c9-4d0e-8f1a-2b3c4d5e6f70")
OTHER_ORG_ID: Final = uuid.UUID("e5f6a7b8-c9d0-4e1f-9a2b-3c4d5e6f7a81")
PUBLIC_URL: Final = "https://admino.example.ch"
LINK_PREFIX: Final = PUBLIC_URL + "/reset-password#token="
TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")
# What the fake upsert stores as the reset token's lifetime.
FAKE_LIFETIME: Final = timedelta(minutes=30)

# GH-153: the display names of the two well-known orgs, the invitation link and
# the invitations CHECK's lifetime cap (migration 0010).
ORG_NAME: Final = "Treuhand Muster AG"
OTHER_ORG_NAME: Final = "Beispiel Partner GmbH"
INVITE_LINK_PREFIX: Final = PUBLIC_URL + "/accept-invitation#token="
INVITATION_MAX_LIFETIME: Final = timedelta(hours=72)

# ---------------------------------------------------------------------------
# Formatting-tolerant session predicates (normalized SQL: lowercase, single
# spaces). Shared by the fake and by the tests that pin the SQL, so both read
# the same predicate the same way.
# ---------------------------------------------------------------------------

NOW_SQL: Final = r"(?:now\(\)|current_timestamp)"
_COL: Final = r"(?:\w+\.)?"
_IDLE_INTERVAL: Final = (
    rf"(?:make_interval\( ?mins ?=> ?{_COL}idle_timeout_minutes ?\)"
    rf"|{_COL}idle_timeout_minutes ?\* ?interval '1 minutes?'"
    rf"|interval '1 minutes?' ?\* ?{_COL}idle_timeout_minutes)"
)
_IDLE_DEADLINE: Final = rf"\(?{_COL}last_seen_at ?\+ ?{_IDLE_INTERVAL}\)?"
# A row that is gone: expired, or idle past its own timeout ("<=" means gone).
EXPIRED_RE: Final = rf"(?:{_COL}expires_at ?<= ?{NOW_SQL}|{NOW_SQL} ?>= ?{_COL}expires_at)"
IDLE_GONE_RE: Final = rf"(?:{_IDLE_DEADLINE} ?<= ?{NOW_SQL}|{NOW_SQL} ?>= ?{_IDLE_DEADLINE})"
# A row that is live: not expired and not idle past its timeout.
LIVE_EXPIRY_RE: Final = rf"(?:{_COL}expires_at ?> ?{NOW_SQL}|{NOW_SQL} ?< ?{_COL}expires_at)"
LIVE_IDLE_RE: Final = rf"(?:{_IDLE_DEADLINE} ?> ?{NOW_SQL}|{NOW_SQL} ?< ?{_IDLE_DEADLINE})"
# "id = $n" as a whole identifier (not user_id / session_id), optionally qualified.
ID_PARAM_RE: Final = r"(?<![\w.])(?:\w+\.)?id = \$(\d+)"
USER_ID_PARAM_RE: Final = r"(?<![\w])(?:\w+\.)?user_id = \$(\d+)"
ORG_ID_PARAM_RE: Final = r"(?<![\w])(?:\w+\.)?org_id = \$(\d+)"

# The columns of the sessions table after migration 0009.
_SESSION_COLUMNS: Final = frozenset(
    {
        "id",
        "token_hash",
        "user_id",
        "created_at",
        "last_seen_at",
        "expires_at",
        "idle_timeout_minutes",
        "ip",
        "user_agent",
    }
)
_MAX_LIFETIME: Final = timedelta(hours=72)

# The columns of the tables the SQL reader models (migrations 0004 and 0010).
_USER_COLUMNS: Final = frozenset(
    {
        "id",
        "email",
        "name",
        "password_hash",
        "kind",
        "org_id",
        "role",
        "status",
        "ui_language",
        "response_language",
        "created_at",
        "last_login_at",
        "deleted_at",
    }
)
_ORG_COLUMNS: Final = frozenset(
    {
        "id",
        "name",
        "status",
        "seats",
        "monthly_budget_chf",
        "storage_quota_bytes",
        "data_residency",
        "default_response_language",
        "deletion_requested_at",
        "purge_after",
        "created_at",
        "updated_at",
    }
)
_INVITATION_COLUMNS: Final = frozenset(
    {"id", "user_id", "token_hash", "created_at", "sent_at", "expires_at", "accepted_at"}
)
_COLUMNS: Final[dict[str, frozenset[str]]] = {
    "users": _USER_COLUMNS,
    "organizations": _ORG_COLUMNS,
    "invitations": _INVITATION_COLUMNS,
}


def norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def sha256(token: str) -> bytes:
    """The stored form of a token: its raw SHA-256 digest."""
    return hashlib.sha256(token.encode()).digest()


def fake_hash(password: str) -> str:
    """The fast stand-in for passwords.hash_password."""
    return "fake$" + hashlib.sha256(password.encode()).hexdigest()


def plain(value: Any) -> uuid.UUID:
    """A plain uuid.UUID from an asyncpg UUID (or a plain one)."""
    return uuid.UUID(int=value.int)


def _pg(value: uuid.UUID | None) -> Any:
    """The asyncpg UUID a driver row would carry."""
    return None if value is None else PgUUID(str(value))


@dataclass(frozen=True)
class NowPlus:
    """A VALUES expression computed on the database clock: ``now() + $n::interval``.

    ``interval`` is the bound value of ``$n``.
    """

    interval: Any


_PLACEHOLDER_RE: Final = re.compile(r"\$(\d+)(?: ?:: ?\w+)?")
_NOW_PLUS_RE: Final = re.compile(rf"\(?{NOW_SQL} ?\+ ?\$(\d+) ?:: ?interval\)?")


def _split_top_level(text: str) -> list[str]:
    """Split at commas outside parentheses."""
    items: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return [item for item in items if item]


def insert_values(sql: str, args: tuple[Any, ...]) -> dict[str, Any]:
    """Map each column of an ``INSERT INTO t (cols) VALUES (exprs)`` to its bound value.

    A plain bind parameter (``$n``, optionally cast with ``::type``) maps to
    ``args[n - 1]``; ``now() + $n::interval`` maps to ``NowPlus(args[n - 1])``.
    Any other VALUES expression fails the calling test: every value must travel
    as a bind parameter.
    """
    normalized = norm(sql)
    match = re.search(r"insert into \w+ ?\(([^)]*)\) ?values ?\((.*)\)", normalized)
    assert match is not None, sql
    columns = [column.strip().strip('"') for column in match.group(1).split(",")]
    expressions = _split_top_level(match.group(2))
    assert len(columns) == len(expressions), sql
    row: dict[str, Any] = {}
    for column, expression in zip(columns, expressions, strict=True):
        placeholder = _PLACEHOLDER_RE.fullmatch(expression)
        if placeholder is not None:
            row[column] = args[int(placeholder.group(1)) - 1]
            continue
        now_plus = _NOW_PLUS_RE.fullmatch(expression)
        assert now_plus is not None, f"{column} is not a bind parameter: {expression}"
        row[column] = NowPlus(args[int(now_plus.group(1)) - 1])
    return row


def _where(normalized: str) -> str:
    """The text after the first WHERE ('' when there is none)."""
    return normalized.split(" where ", 1)[1] if " where " in normalized else ""


def _bound(args: tuple[Any, ...], pattern: str, text: str) -> Any:
    """The bind argument of the first ``<column> = $n`` the pattern finds (None if absent)."""
    match = re.search(pattern, text)
    return None if match is None else args[int(match.group(1)) - 1]


@dataclass(frozen=True)
class Call:
    """One recorded statement: the method, SQL, args, the executor and its transaction."""

    method: str
    sql: str
    args: tuple[Any, ...]
    via: str  # "pool" or "conn-<n>"
    tx: int | None  # the transaction id when run inside conn.transaction()

    @property
    def normalized(self) -> str:
        """The SQL, whitespace-collapsed and lowercased."""
        return norm(self.sql)


class AuditWriteError(Exception):
    """What the fake raises for an audit INSERT when ``fail_audit`` is set."""


class FakeDb:
    """In-memory tables behind a pool-shaped object (see the module docstring)."""

    def __init__(self) -> None:
        self.users: dict[uuid.UUID, dict[str, Any]] = {}
        self.orgs: dict[uuid.UUID, dict[str, Any]] = {}
        self.invitations: dict[uuid.UUID, dict[str, Any]] = {}
        self.tokens: dict[uuid.UUID, dict[str, Any]] = {}
        self.sessions: dict[bytes, dict[str, Any]] = {}
        self.outbox: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.calls: list[Call] = []
        self.transactions: list[tuple[int, str]] = []
        self.fail_audit = False
        self.after_token_lookup: Callable[[], None] | None = None
        self.after_invitation_lookup: Callable[[], None] | None = None
        self.pool = FakePool(self)
        self._connection_count = 0
        self._transaction_count = 0

    # -- fixtures ------------------------------------------------------------

    def add_org(
        self,
        org_id: uuid.UUID | None = None,
        *,
        name: str | None = None,
        seats: int | None = None,
        status: str | None = None,
    ) -> uuid.UUID:
        """Create an organization, or change the given fields of an existing one.

        A new org is active with 100 seats; ORG_ID and OTHER_ORG_ID get
        ORG_NAME and OTHER_ORG_NAME, any other org a generated name. A
        pending_deletion org has its deletion dates set (the 0004 CHECKs).
        Returns the org's id (a plain uuid.UUID).
        """
        org_id = org_id or uuid.uuid4()
        row = self.orgs.get(org_id)
        if row is None:
            default_names = {ORG_ID: ORG_NAME, OTHER_ORG_ID: OTHER_ORG_NAME}
            now = datetime.now(UTC)
            row = {
                "id": org_id,
                "name": default_names.get(org_id, f"Org {org_id.hex[:8]}"),
                "status": "active",
                "seats": 100,
                "monthly_budget_chf": 0,
                "storage_quota_bytes": 0,
                "data_residency": True,
                "default_response_language": "en",
                "deletion_requested_at": None,
                "purge_after": None,
                "created_at": now,
                "updated_at": now,
            }
            self.orgs[org_id] = row
        if name is not None:
            row["name"] = name
        if seats is not None:
            row["seats"] = seats
        if status is not None:
            row["status"] = status
            pending = status == "pending_deletion"
            now = datetime.now(UTC)
            row["deletion_requested_at"] = now if pending else None
            row["purge_after"] = now + timedelta(days=30) if pending else None
        return org_id

    def add_account(
        self,
        *,
        kind: str = "member",
        role: str | None = "editor",
        status: str = "active",
        org_status: str | None = None,
        deleted_at: datetime | None = None,
        email: str | None = None,
        password_hash: str | None = "fake$initial",  # noqa: S107 - a fake stored hash
        ui_language: str = "de",
        org_id: uuid.UUID = ORG_ID,
        name: str | None = "Some Person",
    ) -> uuid.UUID:
        """Add an account and return its id (a plain uuid.UUID).

        A member's org is created (active, 100 seats) if it doesn't exist.
        ``org_status`` overrides the org's status for this account's login,
        session and reset lookups only; left out, the account follows the
        organizations row.
        """
        user_id = uuid.uuid4()
        is_member = kind == "member"
        if is_member and org_id not in self.orgs:
            self.add_org(org_id)
        self.users[user_id] = {
            "id": user_id,
            "email": email or f"user-{user_id.hex[:8]}@example.test",
            "name": name,
            "kind": kind,
            "org_id": org_id if is_member else None,
            "role": role if is_member else None,
            "status": status,
            "deleted_at": deleted_at,
            "password_hash": password_hash,
            "org_status": org_status if is_member else None,
            "ui_language": ui_language,
            "response_language": None,
            "created_at": datetime.now(UTC) - timedelta(days=1),
            "last_login_at": None,
        }
        return user_id

    def open_session(
        self,
        user_id: uuid.UUID,
        *,
        idle_timeout_minutes: int = 60,
        last_seen_ago: timedelta = timedelta(0),
        expires_in: timedelta = timedelta(hours=12),
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Store a session for the user and return its raw token.

        By default the session is live: seen just now, 60 minutes idle timeout,
        expiring in 12 hours. ``last_seen_ago`` / ``expires_in`` build idle or
        expired sessions (a row the purge job hasn't deleted yet).
        """
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        last_seen_at = now - last_seen_ago
        expires_at = now + expires_in
        created_at = min(last_seen_at, expires_at - timedelta(hours=1))
        self.sessions[sha256(token)] = {
            "session_id": uuid.uuid4(),
            "user_id": user_id,
            "token_hash": sha256(token),
            "created_at": created_at,
            "last_seen_at": last_seen_at,
            "expires_at": expires_at,
            "idle_timeout_minutes": idle_timeout_minutes,
            "ip": ip,
            "user_agent": user_agent,
        }
        return token

    def session(self, token: str) -> dict[str, Any]:
        """The stored session row of a raw token (it must exist)."""
        return self.sessions[sha256(token)]

    def session_id_of(self, token: str) -> uuid.UUID:
        """The id of the stored session of a raw token."""
        return uuid.UUID(int=self.session(token)["session_id"].int)

    def session_revoked(self, token: str) -> bool:
        """True when the session of this raw token is gone: revoking deletes the row (GH-152)."""
        return sha256(token) not in self.sessions

    def sessions_of(self, user_id: uuid.UUID) -> list[dict[str, Any]]:
        """Every stored session row of a user."""
        return [row for row in self.sessions.values() if row["user_id"] == user_id]

    # -- helpers for the assertions -------------------------------------------

    def reset_links(self) -> list[str]:
        """The reset links of every queued password reset email, oldest first."""
        return [
            row["params"]["reset_link"]
            for row in self.outbox
            if row["template_key"] == "password_reset"
        ]

    def issued_token(self, index: int = -1) -> str:
        """The token of a queued reset link (the newest by default)."""
        link = self.reset_links()[index]
        assert link.startswith(LINK_PREFIX), link
        return link[len(LINK_PREFIX) :]

    def matching(self, pattern: str) -> list[Call]:
        """Calls whose normalized SQL matches the regex."""
        return [call for call in self.calls if re.search(pattern, call.normalized)]

    def audit_rows(self, action: str | None = None) -> list[dict[str, Any]]:
        """Stored audit rows (optionally of one action)."""
        return [row for row in self.audit if action is None or row["action"] == action]

    def invitation_emails(self, user_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
        """The queued invitation emails (optionally of one user), oldest first."""
        return [
            row
            for row in self.outbox
            if row["template_key"] == "invitation" and user_id in (None, row["user_id"])
        ]

    def invitation_token(self, user_id: uuid.UUID | None = None, index: int = -1) -> str:
        """The token of a queued invitation link (the newest by default)."""
        link = self.invitation_emails(user_id)[index]["params"]["accept_link"]
        assert link.startswith(INVITE_LINK_PREFIX), link
        return str(link[len(INVITE_LINK_PREFIX) :])

    def user_by_email(self, email: str) -> dict[str, Any] | None:
        """The users row with this email, ignoring capitalization."""
        return next(
            (row for row in self.users.values() if row["email"].lower() == email.lower()), None
        )

    def invitation_of(self, user_id: uuid.UUID) -> dict[str, Any] | None:
        """The invitations row of a user."""
        return next((row for row in self.invitations.values() if row["user_id"] == user_id), None)

    def invitation_by_token(self, token: str) -> dict[str, Any] | None:
        """The invitations row whose hash is this raw token's."""
        digest = sha256(token)
        return next((row for row in self.invitations.values() if row["token_hash"] == digest), None)

    def org_status_of(self, account: dict[str, Any]) -> str | None:
        """The org status a login, session or reset lookup sees for an account."""
        if account["kind"] != "member":
            return None
        if account.get("org_status") is not None:
            return str(account["org_status"])
        org = self.orgs.get(account["org_id"])
        return None if org is None else str(org["status"])

    # -- transactions ------------------------------------------------------------

    def begin(self) -> int:
        """Allocate a transaction id."""
        self._transaction_count += 1
        return self._transaction_count

    def snapshot(self) -> dict[str, Any]:
        """A deep copy of every table."""
        return copy.deepcopy(
            {
                "users": self.users,
                "orgs": self.orgs,
                "invitations": self.invitations,
                "tokens": self.tokens,
                "sessions": self.sessions,
                "outbox": self.outbox,
                "audit": self.audit,
            }
        )

    def restore(self, state: dict[str, Any]) -> None:
        """Put the tables back as they were (a rollback)."""
        self.users = state["users"]
        self.orgs = state["orgs"]
        self.invitations = state["invitations"]
        self.tokens = state["tokens"]
        self.sessions = state["sessions"]
        self.outbox = state["outbox"]
        self.audit = state["audit"]

    def new_connection(self) -> FakeConnection:
        """A new connection on this database."""
        self._connection_count += 1
        return FakeConnection(self, f"conn-{self._connection_count}")

    # -- statement handling ----------------------------------------------------

    def handle(self, method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        """Record one statement and apply it to the tables."""
        self.calls.append(Call(method, sql, args, via, tx))
        n = norm(sql)
        if re.search(r"\brevoked_at\b", n):
            # Migration 0009 dropped the column: revoking deletes the row.
            raise asyncpg.exceptions.UndefinedColumnError('column "revoked_at" does not exist')
        if _runs_on_reader(n, args):
            return self._run_statement(method, n, args)
        if n.startswith("insert into audit_events"):
            return self._insert_audit(n, args)
        if n.startswith("insert into email_outbox"):
            return self._enqueue(args)
        if n.startswith("update email_outbox") and "recipient_user_id" in n:
            return self._cancel_outbox(n, args)
        if n.startswith("insert into password_reset_tokens"):
            return self._upsert_token(args)
        if n.startswith("delete from password_reset_tokens"):
            return self._consume_token(args)
        if method == "fetchrow" and "password_reset_tokens" in n:
            return self._token_row(args)
        if n.startswith("update users set password_hash"):
            return self._set_password(args)
        if n.startswith("insert into sessions"):
            return self._insert_session(method, sql, args)
        if n.startswith("delete from sessions"):
            return self._delete_sessions(method, n, args)
        if n.startswith("update sessions"):
            return self._touch_session(n, args)
        if method == "fetch" and re.search(r"\bfrom sessions\b", n):
            return self._list_sessions(n, args)
        if method == "fetchrow" and "sessions" in n:
            return self._session_row(args)
        if (
            method in {"fetchrow", "fetchval"}
            and re.search(r"\bfrom users\b", n)
            and not any(isinstance(arg, str) for arg in args)
        ):
            return self._user_by_id(method, n, args)
        if method == "fetchrow" and "users" in n:
            return self._account_by_email(args)
        if method == "fetch":
            return []
        if method in {"fetchrow", "fetchval"}:
            return None
        return "OK"

    def _run_statement(self, method: str, n: str, args: tuple[Any, ...]) -> Any:
        """Run one statement through the SQL reader and shape its result like asyncpg."""
        statement = _Statement(self, args, datetime.now(UTC))
        verb = n.split(" ", 1)[0]
        if verb == "select":
            rows = statement.select(n)
            tag = f"SELECT {len(rows)}"
            hook = self.after_invitation_lookup
            if (
                hook is not None
                and _primary_table(n) == "invitations"
                and any(isinstance(arg, bytes | bytearray) for arg in args)
            ):
                self.after_invitation_lookup = None
                hook()
        elif verb == "insert":
            rows, count = statement.insert(n)
            tag = f"INSERT 0 {count}"
        elif verb == "update":
            rows, count = statement.update(n)
            tag = f"UPDATE {count}"
        elif verb == "delete":
            rows, count = statement.delete(n)
            tag = f"DELETE {count}"
        else:
            msg = f"the fake doesn't run this statement: {n}"
            raise AssertionError(msg)
        if method == "execute":
            return tag
        if method == "fetch":
            return rows
        if method == "fetchrow":
            return rows[0] if rows else None
        return next(iter(rows[0].values())) if rows else None

    # -- the tables behind the SQL reader ------------------------------------

    def table_rows(self, table: str) -> list[dict[str, Any]]:
        """The stored rows of a table the SQL reader models."""
        if table == "users":
            return list(self.users.values())
        if table == "organizations":
            return list(self.orgs.values())
        if table == "invitations":
            return list(self.invitations.values())
        msg = f"the fake's SQL reader doesn't model table {table}"
        raise AssertionError(msg)

    def new_row(self, table: str, given: dict[str, Any], now: datetime) -> dict[str, Any]:
        """Build, check and store a new users or invitations row (an INSERT)."""
        if table == "users":
            row: dict[str, Any] = dict.fromkeys(_USER_COLUMNS)
            row.update(id=uuid.uuid4(), status="invited", ui_language="en", created_at=now)
            row.update(given)
            row["org_status"] = None
            self.check_row("users", row, changed=set(_USER_COLUMNS), original=None)
            self.users[row["id"]] = row
            return row
        if table == "invitations":
            row = dict.fromkeys(_INVITATION_COLUMNS)
            row.update(id=uuid.uuid4(), created_at=now, sent_at=now)
            row.update(given)
            self.check_row("invitations", row, changed=set(_INVITATION_COLUMNS), original=None)
            self.invitations[row["id"]] = row
            return row
        msg = f"the fake doesn't insert into {table} (tests create orgs with add_org)"
        raise AssertionError(msg)

    def check_row(
        self,
        table: str,
        row: dict[str, Any],
        *,
        changed: set[str],
        original: dict[str, Any] | None,
    ) -> None:
        """Apply the schema's rules for the written columns, as PostgreSQL would."""
        if table == "users":
            self._check_user(row, changed, original)
        elif table == "invitations":
            self._check_invitation(row, changed, original)
        else:
            msg = f"the invitation flow never writes {table}"
            raise AssertionError(msg)

    def _check_user(
        self, row: dict[str, Any], changed: set[str], original: dict[str, Any] | None
    ) -> None:
        """Migration 0004's users constraints (for the written columns) and its trigger."""
        check = asyncpg.exceptions.CheckViolationError
        if original is not None:
            for column in ("kind", "org_id"):
                if column in changed and row[column] != original[column]:
                    msg = "users.kind and users.org_id can't change"
                    raise check(msg)
        for column in ("email", "kind", "status", "ui_language"):
            if column in changed and row[column] is None:
                msg = f'null value in column "{column}" of relation "users"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        if "email" in changed:
            email = row["email"]
            assert isinstance(email, str), "users.email must be bound as a str"
            if (
                not 3 <= len(email) <= 254
                or any(char.isspace() for char in email)
                or email.find("@") < 1
            ):
                msg = 'new row for relation "users" violates check constraint'
                raise check(msg)
            for other in self.users.values():
                if other["id"] != row["id"] and other["email"].lower() == email.lower():
                    # The driver's text repeats the key, as asyncpg's does.
                    msg = (
                        'duplicate key value violates unique constraint "users_email_lower_key"'
                        f" DETAIL: Key (lower(email))=({email.lower()}) already exists."
                    )
                    raise asyncpg.exceptions.UniqueViolationError(msg)
        rules = (
            ("kind", row["kind"] in {"super_admin", "member"}),
            ("role", row["role"] in {None, "org_admin", "editor", "viewer"}),
            ("status", row["status"] in {"invited", "active", "deactivated"}),
            ("ui_language", row["ui_language"] in {"de", "fr", "en"}),
            ("name", row["name"] is None or 1 <= len(row["name"]) <= 120),
            (
                "password_hash",
                row["password_hash"] is None or 1 <= len(row["password_hash"]) <= 512,
            ),
        )
        for column, valid in rules:
            if column in changed and not valid:
                msg = f'new row for relation "users" violates the {column} check'
                raise check(msg)
        if changed & {"kind", "org_id", "role"}:
            is_super_admin = row["kind"] == "super_admin"
            if is_super_admin != (row["org_id"] is None) or is_super_admin != (row["role"] is None):
                msg = 'new row for relation "users" violates the super admin checks'
                raise check(msg)
        if (
            changed & {"status", "name", "password_hash"}
            and row["status"] == "active"
            and (row["name"] is None or row["password_hash"] is None)
        ):
            msg = 'new row for relation "users" violates "users_active_credentials_check"'
            raise check(msg)
        if "org_id" in changed and row["org_id"] is not None and row["org_id"] not in self.orgs:
            msg = 'insert or update on table "users" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)

    def _check_invitation(
        self, row: dict[str, Any], changed: set[str], original: dict[str, Any] | None
    ) -> None:
        """Migration 0010's invitations constraints."""
        del original
        check = asyncpg.exceptions.CheckViolationError
        for column in ("id", "user_id", "token_hash", "created_at", "sent_at", "expires_at"):
            if row[column] is None:
                msg = f'null value in column "{column}" of relation "invitations"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        if "token_hash" in changed:
            token_hash = row["token_hash"]
            if not isinstance(token_hash, bytes | bytearray) or len(token_hash) != 32:
                msg = 'new row for relation "invitations" violates the token_hash check'
                raise check(msg)
        if "user_id" in changed and row["user_id"] not in self.users:
            msg = 'insert or update on table "invitations" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        for other in self.invitations.values():
            if other["id"] == row["id"]:
                continue
            for column in ("user_id", "token_hash"):
                if column in changed and other[column] == row[column]:
                    msg = (
                        f'duplicate key value violates unique constraint "invitations_{column}_key"'
                    )
                    raise asyncpg.exceptions.UniqueViolationError(msg)
        sent_at, expires_at = row["sent_at"], row["expires_at"]
        if not sent_at >= row["created_at"]:
            msg = 'new row for relation "invitations" violates the sent_at check'
            raise check(msg)
        if not (expires_at > sent_at and expires_at <= sent_at + INVITATION_MAX_LIFETIME):
            msg = 'new row for relation "invitations" violates the expiry check'
            raise check(msg)

    def delete_row(self, table: str, row: dict[str, Any]) -> None:
        """Delete one users or invitations row; a user's rows cascade (ON DELETE CASCADE)."""
        if table == "invitations":
            del self.invitations[row["id"]]
            return
        assert table == "users", f"the invitation flow never deletes from {table}"
        user_id = row["id"]
        del self.users[user_id]
        self.invitations = {
            key: value for key, value in self.invitations.items() if value["user_id"] != user_id
        }
        self.outbox = [value for value in self.outbox if value["user_id"] != user_id]
        self.sessions = {
            key: value for key, value in self.sessions.items() if value["user_id"] != user_id
        }
        self.tokens.pop(user_id, None)

    def _insert_audit(self, n: str, args: tuple[Any, ...]) -> str:
        if self.fail_audit:
            raise AuditWriteError("the audit write was refused")
        row = insert_values(n, args)
        row["target_ids"] = json.loads(row["target_ids"])
        row["metadata"] = json.loads(row["metadata"])
        row["ip"] = None if row["ip"] is None else str(row["ip"])
        self.audit.append(row)
        return "INSERT 0 1"

    def _enqueue(self, args: tuple[Any, ...]) -> Any:
        # email_outbox.enqueue_email binds (user_id, template_key, params_json).
        user_id, template_key, params_json = args
        account = self.users.get(plain(user_id))
        if account is None or account["deleted_at"] is not None:
            return None
        self.outbox.append(
            {
                "user_id": plain(user_id),
                "template_key": template_key,
                "language": account["ui_language"],
                "params": json.loads(params_json),
                "status": "pending",
                "finished_at": None,
            }
        )
        return uuid.uuid4()

    def _cancel_outbox(self, n: str, args: tuple[Any, ...]) -> str:
        """Cancel a recipient's pending emails of one template (a resend's stale link).

        Only the shape the spec allows: scoped by recipient and template to pending rows,
        marked failed with params cleared and finished_at set (the outbox's finished-row
        invariant). Anything else fails loudly.
        """
        required = (
            r"^update email_outbox set ",
            r"\bstatus = 'failed'",
            r"\bparams = '\{\}'(?:::jsonb)?",
            rf"\bfinished_at = {NOW_SQL}",
            r"\brecipient_user_id = \$\d+",
            r"\btemplate_key = (?:\$\d+|'invitation')",
            r"\bstatus = 'pending'",
        )
        missing = [pattern for pattern in required if not re.search(pattern, n)]
        assert not missing, f"unexpected email_outbox update: {n!r} (missing {missing})"
        user_id = plain(_bound(args, r"\brecipient_user_id = \$(\d+)", n))
        template_match = re.search(r"\btemplate_key = \$(\d+)", n)
        template = args[int(template_match.group(1)) - 1] if template_match else "invitation"
        now = datetime.now(UTC)
        count = 0
        for row in self.outbox:
            if (
                row["user_id"] == user_id
                and row["template_key"] == template
                and row["status"] == "pending"
            ):
                row.update(status="failed", params={}, finished_at=now)
                count += 1
        return f"UPDATE {count}"

    def _upsert_token(self, args: tuple[Any, ...]) -> datetime:
        token_hash = next(arg for arg in args if isinstance(arg, bytes))
        user_id = plain(next(arg for arg in args if isinstance(arg, uuid.UUID)))
        now = datetime.now(UTC)
        expires_at = now + FAKE_LIFETIME
        self.tokens[user_id] = {
            "token_hash": token_hash,
            "created_at": now,
            "expires_at": expires_at,
        }
        return expires_at

    def _consume_token(self, args: tuple[Any, ...]) -> Any:
        token_hash = next(arg for arg in args if isinstance(arg, bytes))
        user_id = plain(next(arg for arg in args if isinstance(arg, uuid.UUID)))
        row = self.tokens.get(user_id)
        if row is None or row["token_hash"] != token_hash:
            return None
        if not row["expires_at"] > datetime.now(UTC):
            return None
        del self.tokens[user_id]
        return _pg(user_id)

    def _token_row(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        token_hash = next((arg for arg in args if isinstance(arg, bytes)), None)
        found: dict[str, Any] | None = None
        for user_id, row in self.tokens.items():
            if row["token_hash"] == token_hash:
                account = self.users[user_id]
                found = {
                    "user_id": _pg(user_id),
                    "email": account["email"],
                    "kind": account["kind"],
                    "org_id": _pg(account["org_id"]),
                    "role": account["role"],
                    "status": account["status"],
                    "deleted_at": account["deleted_at"],
                    "org_status": self.org_status_of(account),
                    "expires_at": row["expires_at"],
                }
                break
        if self.after_token_lookup is not None:
            self.after_token_lookup()
        return found

    def _set_password(self, args: tuple[Any, ...]) -> str:
        new_hash = next(arg for arg in args if isinstance(arg, str))
        user_id = plain(next(arg for arg in args if isinstance(arg, uuid.UUID)))
        if user_id not in self.users:
            return "UPDATE 0"
        self.users[user_id]["password_hash"] = new_hash
        return "UPDATE 1"

    # -- sessions ----------------------------------------------------------------

    def _insert_session(self, method: str, sql: str, args: tuple[Any, ...]) -> Any:
        values = insert_values(sql, args)
        unknown = set(values) - _SESSION_COLUMNS
        if unknown:
            msg = f'column "{sorted(unknown)[0]}" of relation "sessions" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        for column in ("token_hash", "user_id", "expires_at", "idle_timeout_minutes"):
            if values.get(column) is None:
                msg = f'null value in column "{column}" of relation "sessions"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        now = datetime.now(UTC)
        created_at = values.get("created_at") or now
        expires_at = values["expires_at"]
        if isinstance(expires_at, NowPlus):
            assert isinstance(expires_at.interval, timedelta), expires_at
            expires_at = now + expires_at.interval
        idle = values["idle_timeout_minutes"]
        if type(idle) is not int or not 15 <= idle <= 480:
            msg = "sessions idle_timeout_minutes check"
            raise asyncpg.exceptions.CheckViolationError(msg)
        if not created_at < expires_at <= created_at + _MAX_LIFETIME:
            msg = "sessions expiry check"
            raise asyncpg.exceptions.CheckViolationError(msg)
        user_agent = values.get("user_agent")
        if user_agent is not None and len(user_agent) > 256:
            msg = "sessions user_agent check"
            raise asyncpg.exceptions.CheckViolationError(msg)
        ip = values.get("ip")
        session_id = uuid.uuid4()
        self.sessions[values["token_hash"]] = {
            "session_id": session_id,
            "user_id": plain(values["user_id"]),
            "token_hash": values["token_hash"],
            "created_at": created_at,
            "last_seen_at": values.get("last_seen_at") or now,
            "expires_at": expires_at,
            "idle_timeout_minutes": idle,
            "ip": None if ip is None else str(ip),
            "user_agent": user_agent,
        }
        if method == "fetchval":
            return _pg(session_id)
        if method == "fetchrow":
            return {"id": _pg(session_id)}
        return "INSERT 0 1"

    def _delete_sessions(self, method: str, n: str, args: tuple[Any, ...]) -> Any:
        now = datetime.now(UTC)
        where = _where(n)
        if "org_id" in where or re.search(r"\busing users\b", n):
            # Every session of the org's users (revoke_org_sessions).
            org_id = plain(next(arg for arg in args if isinstance(arg, uuid.UUID)))
            victims = [
                key
                for key, row in self.sessions.items()
                if self.users.get(row["user_id"], {}).get("org_id") == org_id
            ]
        elif not args:
            # The purge: only the predicates the SQL states.
            expired = re.search(EXPIRED_RE, where) is not None
            idle = re.search(IDLE_GONE_RE, where) is not None
            assert expired or idle, f"a sessions purge without a known predicate: {n}"
            victims = [
                key
                for key, row in self.sessions.items()
                if (expired and row["expires_at"] <= now)
                or (
                    idle
                    and row["last_seen_at"] + timedelta(minutes=row["idle_timeout_minutes"]) <= now
                )
            ]
        elif re.search(r"\btoken_hash\b", where):
            token_hash = next(arg for arg in args if isinstance(arg, bytes))
            victims = [token_hash] if token_hash in self.sessions else []
        else:
            user_id = _bound(args, USER_ID_PARAM_RE, where)
            assert user_id is not None, f"a sessions delete not scoped to a user: {n}"
            session_id = _bound(args, ID_PARAM_RE, where)
            victims = [
                key
                for key, row in self.sessions.items()
                if row["user_id"] == plain(user_id)
                and (session_id is None or row["session_id"] == plain(session_id))
            ]
        deleted = [self.sessions.pop(key)["session_id"] for key in victims]
        if method == "fetchval":
            return _pg(deleted[0]) if deleted else None
        if method == "fetchrow":
            return {"id": _pg(deleted[0])} if deleted else None
        if method == "fetch":
            return [{"id": _pg(session_id)} for session_id in deleted]
        return f"DELETE {len(deleted)}"

    def _touch_session(self, n: str, args: tuple[Any, ...]) -> str:
        assert re.match(rf"update\s+sessions\s+set\s+last_seen_at = {NOW_SQL}", n), n
        where = _where(n)
        session_id = _bound(args, ID_PARAM_RE, where)
        now = datetime.now(UTC)
        count = 0
        for row in self.sessions.values():
            if session_id is not None:
                hit = row["session_id"] == plain(session_id)
            else:
                hit = row["token_hash"] == next(arg for arg in args if isinstance(arg, bytes))
            if hit:
                row["last_seen_at"] = now
                count += 1
        return f"UPDATE {count}"

    def _list_sessions(self, n: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        user_id = _bound(args, USER_ID_PARAM_RE, _where(n))
        assert user_id is not None, f"a session list not scoped to a user: {n}"
        now = datetime.now(UTC)
        rows = [row for row in self.sessions.values() if row["user_id"] == plain(user_id)]
        if re.search(LIVE_EXPIRY_RE, n):
            rows = [row for row in rows if row["expires_at"] > now]
        if re.search(LIVE_IDLE_RE, n):
            rows = [
                row
                for row in rows
                if row["last_seen_at"] + timedelta(minutes=row["idle_timeout_minutes"]) > now
            ]
        if re.search(r"order by (?:\w+\.)?last_seen_at desc", n):
            rows.sort(key=lambda row: row["last_seen_at"], reverse=True)
        return [
            {
                "id": _pg(row["session_id"]),
                "created_at": row["created_at"],
                "last_seen_at": row["last_seen_at"],
                "expires_at": row["expires_at"],
                "ip": None if row["ip"] is None else ip_address(row["ip"]),
                "user_agent": row["user_agent"],
            }
            for row in rows
        ]

    def _session_row(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        token_hash = next((arg for arg in args if isinstance(arg, bytes)), None)
        session = self.sessions.get(token_hash) if token_hash is not None else None
        if session is None:
            return None
        account = self.users[session["user_id"]]
        return {
            "session_id": _pg(session["session_id"]),
            "expires_at": session["expires_at"],
            "last_seen_at": session["last_seen_at"],
            "idle_timeout_minutes": session["idle_timeout_minutes"],
            "user_id": _pg(account["id"]),
            "kind": account["kind"],
            "org_id": _pg(account["org_id"]),
            "role": account["role"],
            "status": account["status"],
            "deleted_at": account["deleted_at"],
            "org_status": self.org_status_of(account),
            "ui_language": account["ui_language"],
            "response_language": account["response_language"],
        }

    def _user_by_id(self, method: str, n: str, args: tuple[Any, ...]) -> Any:
        """A users lookup by id, applying the org and deleted_at filters its SQL states."""
        where = _where(n)
        user_id = _bound(args, ID_PARAM_RE, where)
        assert user_id is not None, f"a users lookup without id = $n: {n}"
        account = self.users.get(plain(user_id))
        if account is None:
            return None
        org_match = re.search(ORG_ID_PARAM_RE, where)
        if org_match is not None:
            org_id = args[int(org_match.group(1)) - 1]
            if account["org_id"] is None or org_id is None or account["org_id"] != plain(org_id):
                return None
        if re.search(r"(?:\w+\.)?deleted_at is null", where) and account["deleted_at"] is not None:
            return None
        if method == "fetchval":
            return _pg(account["id"])
        return {
            "id": _pg(account["id"]),
            "kind": account["kind"],
            "org_id": _pg(account["org_id"]),
            "role": account["role"],
            "status": account["status"],
            "deleted_at": account["deleted_at"],
        }

    def _account_by_email(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        email = next((arg for arg in args if isinstance(arg, str)), None)
        if email is None:
            return None
        for account in self.users.values():
            if account["email"].casefold() == email.casefold():
                return {
                    **account,
                    "id": _pg(account["id"]),
                    "org_id": _pg(account["org_id"]),
                    "org_status": self.org_status_of(account),
                }
        return None


# ---------------------------------------------------------------------------
# The SQL reader behind the users, organizations and invitations statements
# (GH-153). It reads normalized SQL (lowercase, single spaces).
# ---------------------------------------------------------------------------


def _masked(text: str) -> str:
    """Blank out quoted literals and everything inside parentheses (same length).

    The outermost parentheses stay, so top-level structure (keywords, commas,
    operators) can be found in the masked text and sliced from the original.
    """
    out: list[str] = []
    depth = 0
    quoted = False
    for char in text:
        if quoted:
            quoted = char != "'"
            out.append("'" if not quoted and depth == 0 else " ")
        elif char == "'":
            quoted = True
            out.append("'" if depth == 0 else " ")
        elif char == "(":
            out.append("(" if depth == 0 else " ")
            depth += 1
        elif char == ")":
            depth -= 1
            out.append(")" if depth == 0 else " ")
        else:
            out.append(char if depth == 0 else " ")
    assert depth == 0 and not quoted, f"unbalanced SQL: {text}"
    return "".join(out)


def _top_split(text: str, pattern: str) -> list[str]:
    """Split text at the top-level matches of a regex (outside parentheses and literals)."""
    masked = _masked(text)
    parts: list[str] = []
    start = 0
    for match in re.finditer(pattern, masked):
        parts.append(text[start : match.start()].strip())
        start = match.end()
    parts.append(text[start:].strip())
    return parts


def _unwrap(text: str) -> str:
    """Drop parentheses that wrap the whole expression."""
    text = text.strip()
    while text.startswith("(") and _masked(text).find(")") == len(text) - 1:
        text = text[1:-1].strip()
    return text


def _clauses(text: str, keywords: tuple[str, ...]) -> dict[str, str]:
    """Cut a statement into its top-level clauses, keyed by the keyword that opens each."""
    masked = _masked(text)
    found: list[tuple[int, str]] = []
    for keyword in keywords:
        hits = list(re.finditer(rf"(?<![\w.]){re.escape(keyword)}(?!\w)", masked))
        assert len(hits) <= 1, f"the fake can't read two {keyword!r} clauses: {text}"
        if hits:
            found.append((hits[0].start(), keyword))
    found.sort()
    assert found and found[0][0] == 0, f"the fake can't read this statement: {text}"
    clauses: dict[str, str] = {}
    for index, (start, keyword) in enumerate(found):
        end = found[index + 1][0] if index + 1 < len(found) else len(text)
        clauses[keyword] = text[start + len(keyword) : end].strip()
    return clauses


@dataclass(frozen=True)
class _Source:
    """One table of a FROM / JOIN / USING list: its alias, ON condition and join kind."""

    table: str
    alias: str
    on: str | None
    left: bool


def _sources(text: str) -> list[_Source]:
    """The tables of a FROM (or USING) list, in order."""
    masked = _masked(text)
    pieces: list[tuple[str, str]] = []
    start = 0
    kind = "first"
    for match in re.finditer(r" ?, ?| (?:(inner|left(?: outer)?|cross|right|full) )?join ", masked):
        pieces.append((kind, text[start : match.start()].strip()))
        kind = "comma" if "," in match.group(0) else (match.group(1) or "inner")
        start = match.end()
    pieces.append((kind, text[start:].strip()))
    sources: list[_Source] = []
    for kind, piece in pieces:
        assert kind in {"first", "comma", "inner", "left", "left outer"}, (
            f"the fake doesn't do {kind} joins: {text}"
        )
        match = re.fullmatch(r"(?:only )?(\w+)(?: (?:as )?(?!on\b)(\w+))?(?: on (.+))?", piece)
        assert match is not None, f"the fake can't read this FROM item: {piece}"
        table, alias, on = match.groups()
        assert table in _COLUMNS, f"the fake's SQL reader doesn't model table {table}: {text}"
        assert (on is None) == (kind in {"first", "comma"}), f"a join needs ON: {piece}"
        sources.append(_Source(table, alias or table, on, kind.startswith("left")))
    return sources


def _primary_table(n: str) -> str | None:
    """The table a statement writes, or the first table its (outermost) SELECT reads."""
    match = re.match(r"(?:insert into|update|delete from) (?:only )?(\w+)", n)
    if match is not None:
        return match.group(1)
    match = re.search(r"(?<![\w.])from (\w+)", _masked(n)) or re.search(r"(?<![\w.])from (\w+)", n)
    return None if match is None else match.group(1)


def _runs_on_reader(n: str, args: tuple[Any, ...]) -> bool:
    """True for the statements the SQL reader runs (see the module docstring)."""
    if re.search(r"\binvitations\b", n):
        return True
    table = _primary_table(n)
    if table == "organizations":
        return True
    if table != "users":
        return False
    if re.match(r"(?:insert into|update|delete from) users\b", n):
        return True
    where = _where(n)
    return (
        re.search(ORG_ID_PARAM_RE, where) is not None
        and re.search(ID_PARAM_RE, where) is None
        and not any(isinstance(arg, str) for arg in args)
    )


def _store(value: Any) -> Any:
    """What a table keeps: a plain uuid.UUID for any UUID, other values unchanged."""
    return uuid.UUID(int=value.int) if isinstance(value, uuid.UUID) else value


def _canonical(value: Any) -> Any:
    """A comparable value: plain UUIDs, bytes for bytearrays."""
    if isinstance(value, uuid.UUID):
        return uuid.UUID(int=value.int)
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def _compare(operator: str, left: Any, right: Any) -> bool:
    """SQL comparison: anything compared with NULL is not true."""
    if left is None or right is None:
        return False
    left, right = _canonical(left), _canonical(right)
    if isinstance(left, uuid.UUID) and isinstance(right, str):
        right = uuid.UUID(right)
    if isinstance(right, uuid.UUID) and isinstance(left, str):
        left = uuid.UUID(left)
    if operator == "=":
        return bool(left == right)
    if operator in {"<>", "!="}:
        return bool(left != right)
    if operator == "<":
        return bool(left < right)
    if operator == "<=":
        return bool(left <= right)
    if operator == ">":
        return bool(left > right)
    return bool(left >= right)


_Context = dict[str, tuple[str, dict[str, Any] | None]]


class _Statement:
    """One statement the SQL reader runs: the database, its bind args and now()."""

    def __init__(self, db: FakeDb, args: tuple[Any, ...], now: datetime) -> None:
        self.db = db
        self.args = args
        self.now = now

    # -- values and predicates ---------------------------------------------------

    def _arg(self, number: str) -> Any:
        index = int(number) - 1
        assert 0 <= index < len(self.args), f"${number} has no bound value"
        return self.args[index]

    def value(self, expr: str, ctx: _Context) -> Any:
        """Evaluate a value expression in a row context."""
        expr = _unwrap(expr)
        if match := re.fullmatch(r"\$(\d+)(?: ?:: ?\w+(?: \w+)?)?", expr):
            return self._arg(match.group(1))
        if match := re.fullmatch(r"'((?:[^']|'')*)'(?: ?:: ?\w+)?", expr):
            return match.group(1).replace("''", "'")
        if expr == "null":
            return None
        if expr in {"true", "false"}:
            return expr == "true"
        if re.fullmatch(r"-?\d+", expr):
            return int(expr)
        if re.fullmatch(NOW_SQL, expr):
            return self.now
        if match := re.fullmatch(rf"{NOW_SQL} ?\+ ?\$(\d+) ?:: ?interval", expr):
            interval = self._arg(match.group(1))
            assert isinstance(interval, timedelta), "an interval must be bound as a timedelta"
            return self.now + interval
        if match := re.fullmatch(r"lower ?\((.+)\)", expr):
            inner = self.value(match.group(1), ctx)
            return inner.lower() if isinstance(inner, str) else inner
        if match := re.fullmatch(r"(?:(\w+)\.)?(\w+)", expr):
            return self.column(match.group(1), match.group(2), ctx)
        msg = f"the fake can't evaluate {expr!r}"
        raise AssertionError(msg)

    def column(self, qualifier: str | None, name: str, ctx: _Context) -> Any:
        """A column's value in a row context, resolved like PostgreSQL."""
        if qualifier is not None:
            if qualifier not in ctx:
                msg = f'missing FROM-clause entry for table "{qualifier}"'
                raise asyncpg.exceptions.UndefinedTableError(msg)
            owners = [qualifier] if name in _COLUMNS[ctx[qualifier][0]] else []
        else:
            owners = [alias for alias, (table, _) in ctx.items() if name in _COLUMNS[table]]
        if len(owners) > 1:
            msg = f'column reference "{name}" is ambiguous'
            raise asyncpg.exceptions.AmbiguousColumnError(msg)
        if not owners:
            msg = f'column "{name}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        row = ctx[owners[0]][1]
        return None if row is None else row[name]

    def holds(self, text: str, ctx: _Context) -> bool:
        """True when every AND-ed predicate of a WHERE / ON text holds."""
        text = _unwrap(text)
        masked = _masked(text)
        for keyword in ("or", "between", "exists", "like", "ilike", "any", "all", "case"):
            assert not re.search(rf"(?<![\w.]){keyword}(?!\w)", masked), (
                f"the fake doesn't evaluate {keyword.upper()}: {text}"
            )
        return all(self.atom(atom, ctx) for atom in _top_split(text, r" and "))

    def atom(self, atom: str, ctx: _Context) -> bool:
        """Evaluate one predicate."""
        atom = _unwrap(atom)
        if " and " in _masked(atom):
            return self.holds(atom, ctx)
        masked = _masked(atom)
        if match := re.fullmatch(r"(.+?) is (not )?null", masked):
            value = self.value(atom[: match.end(1)], ctx)
            return (value is not None) if match.group(2) else (value is None)
        if match := re.fullmatch(r"(.+?) (not )?in ?\( *\)", masked):
            left = self.value(atom[: match.end(1)], ctx)
            inner = atom[masked.rindex("(") + 1 : -1].strip()
            if inner.startswith("select "):
                values = [next(iter(row.values())) for row in self.select(inner)]
            else:
                values = [self.value(item, ctx) for item in _top_split(inner, ",")]
            found = any(_compare("=", left, value) for value in values)
            return left is not None and (found != bool(match.group(2)))
        assert not re.match(r"not ", masked), f"the fake doesn't evaluate NOT: {atom}"
        if match := re.fullmatch(r"(.+?) ?(<>|!=|<=|>=|=|<|>) ?(.+)", masked):
            left = self.value(atom[: match.end(1)], ctx)
            right = self.value(atom[match.start(3) :], ctx)
            return _compare(match.group(2), left, right)
        msg = f"the fake can't evaluate the predicate {atom!r}"
        raise AssertionError(msg)

    # -- row sets ----------------------------------------------------------------

    def contexts(self, sources: list[_Source]) -> list[_Context]:
        """Every combination of source rows that satisfies the ON conditions."""
        contexts: list[_Context] = [{}]
        for source in sources:
            joined: list[_Context] = []
            for ctx in contexts:
                matched = [
                    candidate
                    for row in self.db.table_rows(source.table)
                    if (candidate := {**ctx, source.alias: (source.table, row)})
                    and (source.on is None or self.holds(source.on, candidate))
                ]
                if not matched and source.left:
                    matched = [{**ctx, source.alias: (source.table, None)}]
                joined.extend(matched)
            contexts = joined
        return contexts

    def filtered(self, contexts: list[_Context], where: str | None) -> list[_Context]:
        return contexts if where is None else [ctx for ctx in contexts if self.holds(where, ctx)]

    def ordered(self, contexts: list[_Context], text: str) -> list[_Context]:
        """Sort by an ORDER BY list (NULLs last ascending, first descending, as PostgreSQL)."""
        keys = []
        for piece in _top_split(text, ","):
            match = re.fullmatch(r"(.+?)(?: (asc|desc))?(?: nulls (first|last))?", piece)
            assert match is not None, f"the fake can't read ORDER BY {piece}"
            keys.append(match.groups())
        for expr, direction, nulls in reversed(keys):
            descending = direction == "desc"
            nulls_first = (nulls == "first") if nulls else descending
            present = [ctx for ctx in contexts if self.value(expr, ctx) is not None]
            absent = [ctx for ctx in contexts if self.value(expr, ctx) is None]
            present.sort(key=lambda ctx, e=expr: _canonical(self.value(e, ctx)), reverse=descending)
            contexts = absent + present if nulls_first else present + absent
        return contexts

    def project(self, text: str, contexts: list[_Context]) -> list[dict[str, Any]]:
        """Evaluate a SELECT / RETURNING list over the row contexts (asyncpg-shaped values)."""
        items = []
        for item in _top_split(text, ","):
            masked = _masked(item)
            alias = None
            expr = item
            match = re.fullmatch(r"(.+?) as (\w+)", masked) or re.fullmatch(
                r"((?:\w+\.)?\w+) (\w+)", masked
            )
            if match is not None:
                expr, alias = item[: match.end(1)], match.group(2)
            expr = expr.strip()
            assert expr != "*" and not expr.endswith(".*"), "name the columns (no SELECT *)"
            if count := re.fullmatch(r"count ?\((\*|1|(?:\w+\.)?\w+)\)(?: ?:: ?\w+)?", expr):
                items.append(("count", alias or "count", count.group(1)))
            elif re.fullmatch(r"(?:\w+\.)?\w+", expr) and not re.fullmatch(r"-?\d+|null", expr):
                items.append(("value", alias or expr.rsplit(".", 1)[-1], expr))
            elif re.search(r"<>|!=|<=|>=|=|<|>| is (?:not )?null$", _masked(expr)):
                items.append(("predicate", alias or "?column?", expr))
            else:
                items.append(("value", alias or "?column?", expr))
        if any(kind == "count" for kind, _, _ in items):
            assert all(kind == "count" for kind, _, _ in items), "no GROUP BY in the fake"
            return [
                {
                    key: sum(
                        1
                        for ctx in contexts
                        if expr in {"*", "1"} or self.value(expr, ctx) is not None
                    )
                    for _, key, expr in items
                }
            ]
        rows = []
        for ctx in contexts:
            row: dict[str, Any] = {}
            for kind, key, expr in items:
                value = self.atom(expr, ctx) if kind == "predicate" else self.value(expr, ctx)
                row[key] = _pg(value) if isinstance(value, uuid.UUID) else value
            rows.append(row)
        return rows

    # -- statements --------------------------------------------------------------

    def select(self, n: str) -> list[dict[str, Any]]:
        masked = _masked(n)
        if match := re.fullmatch(r"select exists ?\( *\)(?: as (\w+))?", masked):
            inner = n[masked.index("(") + 1 : masked.rindex(")")].strip()
            return [{match.group(1) or "exists": bool(self.select(inner))}]
        clauses = _clauses(
            n,
            (
                "select",
                "from",
                "where",
                "group by",
                "having",
                "order by",
                "limit",
                "offset",
                "for update",
                "for no key update",
                "for share",
                "for key share",
            ),
        )
        unsupported = {"group by", "having", "offset", "for share", "for key share"}
        assert not unsupported & clauses.keys(), f"the fake can't read this SELECT: {n}"
        assert "from" in clauses, f"a SELECT without FROM: {n}"
        assert not clauses["select"].startswith("distinct"), "no DISTINCT in the fake"
        contexts = self.filtered(self.contexts(_sources(clauses["from"])), clauses.get("where"))
        if "order by" in clauses:
            contexts = self.ordered(contexts, clauses["order by"])
        rows = self.project(clauses["select"], contexts)
        if "limit" in clauses:
            rows = rows[: int(self.value(clauses["limit"], {}))]
        return rows

    def insert(self, n: str) -> tuple[list[dict[str, Any]], int]:
        clauses = _clauses(n, ("insert into", "values", "on conflict", "returning"))
        assert "on conflict" not in clauses, f"the fake doesn't do ON CONFLICT here: {n}"
        head = re.fullmatch(r"(\w+) ?\((.*)\)", clauses["insert into"])
        values = clauses.get("values", "")
        assert head is not None and _unwrap(values) != values, f"one VALUES row only: {n}"
        table = head.group(1)
        columns = [column.strip().strip('"') for column in head.group(2).split(",")]
        exprs = _top_split(values[1:-1], ",")
        assert len(columns) == len(exprs), n
        unknown = set(columns) - _COLUMNS.get(table, frozenset())
        if unknown:
            msg = f'column "{sorted(unknown)[0]}" of relation "{table}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        given = {
            column: _store(self.value(expr, {}))
            for column, expr in zip(columns, exprs, strict=True)
            if expr != "default"
        }
        row = self.db.new_row(table, given, self.now)
        ctx: _Context = {table: (table, row)}
        returned = self.project(clauses["returning"], [ctx]) if "returning" in clauses else []
        return returned, 1

    def update(self, n: str) -> tuple[list[dict[str, Any]], int]:
        clauses = _clauses(n, ("update", "set", "from", "where", "returning"))
        head = re.fullmatch(r"(?:only )?(\w+)(?: (?:as )?(\w+))?", clauses["update"])
        assert head is not None, n
        table, alias = head.group(1), head.group(2) or head.group(1)
        assert table in {"users", "invitations"}, f"the invitation flow never updates {table}"
        sources = [_Source(table, alias, None, left=False)]
        if "from" in clauses:
            sources += _sources(clauses["from"])
        contexts = self.filtered(self.contexts(sources), clauses.get("where"))
        assignments = []
        for piece in _top_split(clauses["set"], ","):
            match = re.fullmatch(r"(?:\w+\.)?(\w+) ?= ?(.+)", piece)
            assert match is not None, f"the fake can't read SET {piece}"
            if match.group(1) not in _COLUMNS[table]:
                msg = f'column "{match.group(1)}" of relation "{table}" does not exist'
                raise asyncpg.exceptions.UndefinedColumnError(msg)
            assignments.append(match.groups())
        targets: list[tuple[_Context, dict[str, Any], dict[str, Any]]] = []
        seen: set[int] = set()
        for ctx in contexts:
            row = ctx[alias][1]
            assert row is not None
            if id(row) in seen:
                continue
            seen.add(id(row))
            new = {column: _store(self.value(expr, ctx)) for column, expr in assignments}
            targets.append((ctx, row, new))
        for _, row, new in targets:
            self.db.check_row(table, {**row, **new}, changed=set(new), original=row)
        for _, row, new in targets:
            row.update(new)
        returned = (
            self.project(clauses["returning"], [ctx for ctx, _, _ in targets])
            if "returning" in clauses
            else []
        )
        return returned, len(targets)

    def delete(self, n: str) -> tuple[list[dict[str, Any]], int]:
        clauses = _clauses(n, ("delete from", "using", "where", "returning"))
        head = re.fullmatch(r"(?:only )?(\w+)(?: (?:as )?(\w+))?", clauses["delete from"])
        assert head is not None, n
        table, alias = head.group(1), head.group(2) or head.group(1)
        assert table in {"users", "invitations"}, f"the invitation flow never deletes {table}"
        sources = [_Source(table, alias, None, left=False)]
        if "using" in clauses:
            sources += _sources(clauses["using"])
        contexts = self.filtered(self.contexts(sources), clauses.get("where"))
        targets: list[tuple[_Context, dict[str, Any]]] = []
        seen: set[int] = set()
        for ctx in contexts:
            row = ctx[alias][1]
            assert row is not None
            if id(row) not in seen:
                seen.add(id(row))
                targets.append((ctx, row))
        returned = (
            self.project(clauses["returning"], [ctx for ctx, _ in targets])
            if "returning" in clauses
            else []
        )
        for _, row in targets:
            self.db.delete_row(table, row)
        return returned, len(targets)


class FakeConnection:
    """A connection: every statement goes to the fake database, tagged with this
    connection's name and its open transaction."""

    def __init__(self, db: FakeDb, name: str) -> None:
        self._db = db
        self.name = name
        self.tx: int | None = None

    async def execute(self, sql: str, *args: Any) -> Any:
        return self._db.handle("execute", sql, args, self.name, self.tx)

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchrow", sql, args, self.name, self.tx)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchval", sql, args, self.name, self.tx)

    async def fetch(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetch", sql, args, self.name, self.tx)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Snapshot the tables; restore them if the block raises (rollback)."""
        assert self.tx is None, "nested transactions are not expected here"
        tx_id = self._db.begin()
        state = self._db.snapshot()
        self.tx = tx_id
        try:
            yield
        except BaseException as exc:
            self._db.restore(state)
            self._db.transactions.append((tx_id, f"rollback:{type(exc).__name__}"))
            raise
        else:
            self._db.transactions.append((tx_id, "commit"))
        finally:
            self.tx = None

    def is_in_transaction(self) -> bool:
        return self.tx is not None


class FakePool:
    """The pool: statements run outside any transaction; acquire() yields a connection."""

    def __init__(self, db: FakeDb) -> None:
        self._db = db

    async def execute(self, sql: str, *args: Any) -> Any:
        return self._db.handle("execute", sql, args, "pool", None)

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchrow", sql, args, "pool", None)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchval", sql, args, "pool", None)

    async def fetch(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetch", sql, args, "pool", None)

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[FakeConnection]:
        yield self._db.new_connection()
