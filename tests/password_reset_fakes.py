"""Shared in-memory database for the password reset tests (GH-151).

``FakeDb`` stands in for the users, organizations, sessions,
password_reset_tokens, email_outbox and audit_events tables behind a
pool-shaped object (``FakeDb.pool``). The real ``admino.password_reset``,
``admino.sessions``, ``admino.email_outbox`` and ``admino.audit_events`` code
runs against it: each statement is recognised by its table and verb, and its
bind parameters are applied to the in-memory tables, so a test can request a
reset, read the link from the queued email, confirm it and check the result.

Inputs: accounts and sessions added with ``add_account`` / ``open_session``.
Outputs: the recorded calls (``calls``: method, SQL, args, which pool or
connection ran it and inside which transaction), the table state, and the
outcome of every transaction (``transactions``: commit or rollback).

Semantics the tests rely on:
- ``pool.acquire()`` yields a new connection; ``conn.transaction()`` snapshots
  the tables and restores them when the block raises (a rollback), so a
  failure inside a transaction leaves nothing behind, as in PostgreSQL. The
  pool itself has no ``transaction()`` (asyncpg's Pool hasn't either).
- The token upsert keeps one row per user (ON CONFLICT (user_id)) and returns
  its ``expires_at`` (now + 30 minutes); the SQL's own lifetime is pinned by a
  dedicated test, not by this fake.
- The token DELETE only removes the row when the hash, the user and
  ``expires_at > now`` all match, and returns the user id (else None).
- ``fail_audit`` makes every INSERT INTO audit_events fail like a driver
  error; ``after_token_lookup`` runs right after the token lookup (a
  concurrent request, confirm or expiry between the lookup and the consume).
- Rows are returned with asyncpg's own UUID type, as the driver does.

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
from typing import TYPE_CHECKING, Any, Final

from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

ORG_ID: Final = uuid.UUID("d4e5f6a7-b8c9-4d0e-8f1a-2b3c4d5e6f70")
PUBLIC_URL: Final = "https://admino.example.ch"
LINK_PREFIX: Final = PUBLIC_URL + "/reset-password#token="
TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")
# What the fake upsert stores as the token's lifetime.
FAKE_LIFETIME: Final = timedelta(minutes=30)


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
        self.tokens: dict[uuid.UUID, dict[str, Any]] = {}
        self.sessions: dict[bytes, dict[str, Any]] = {}
        self.outbox: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.calls: list[Call] = []
        self.transactions: list[tuple[int, str]] = []
        self.fail_audit = False
        self.after_token_lookup: Callable[[], None] | None = None
        self.pool = FakePool(self)
        self._connection_count = 0
        self._transaction_count = 0

    # -- fixtures ------------------------------------------------------------

    def add_account(
        self,
        *,
        kind: str = "member",
        role: str | None = "editor",
        status: str = "active",
        org_status: str | None = "active",
        deleted_at: datetime | None = None,
        email: str | None = None,
        password_hash: str | None = "fake$initial",  # noqa: S107 - a fake stored hash
        ui_language: str = "de",
    ) -> uuid.UUID:
        """Add an account and return its id (a plain uuid.UUID)."""
        user_id = uuid.uuid4()
        is_member = kind == "member"
        self.users[user_id] = {
            "id": user_id,
            "email": email or f"user-{user_id.hex[:8]}@example.test",
            "name": "Some Person",
            "kind": kind,
            "org_id": ORG_ID if is_member else None,
            "role": role if is_member else None,
            "status": status,
            "deleted_at": deleted_at,
            "password_hash": password_hash,
            "org_status": org_status if is_member else None,
            "ui_language": ui_language,
            "response_language": None,
        }
        return user_id

    def open_session(self, user_id: uuid.UUID, *, revoked: bool = False) -> str:
        """Store a live (or revoked) session for the user and return its raw token."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        self.sessions[sha256(token)] = {
            "session_id": uuid.uuid4(),
            "user_id": user_id,
            "expires_at": now + timedelta(hours=12),
            "revoked_at": now if revoked else None,
        }
        return token

    def session_revoked(self, token: str) -> bool:
        """True when the session of this raw token has been revoked."""
        return self.sessions[sha256(token)]["revoked_at"] is not None

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
                "tokens": self.tokens,
                "sessions": self.sessions,
                "outbox": self.outbox,
                "audit": self.audit,
            }
        )

    def restore(self, state: dict[str, Any]) -> None:
        """Put the tables back as they were (a rollback)."""
        self.users = state["users"]
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
        if n.startswith("insert into audit_events"):
            return self._insert_audit(n, args)
        if n.startswith("insert into email_outbox"):
            return self._enqueue(args)
        if n.startswith("insert into password_reset_tokens"):
            return self._upsert_token(args)
        if n.startswith("delete from password_reset_tokens"):
            return self._consume_token(args)
        if method == "fetchrow" and "password_reset_tokens" in n:
            return self._token_row(args)
        if n.startswith("update users set password_hash"):
            return self._set_password(args)
        if n.startswith("update sessions set revoked_at"):
            return self._revoke(n, args)
        if method == "fetchrow" and "sessions" in n:
            return self._session_row(args)
        if method == "fetchrow" and "users" in n:
            return self._account_by_email(args)
        if method == "fetch":
            return []
        if method in {"fetchrow", "fetchval"}:
            return None
        return "OK"

    def _insert_audit(self, n: str, args: tuple[Any, ...]) -> str:
        if self.fail_audit:
            raise AuditWriteError("the audit write was refused")
        match = re.search(r"\(([^)]*)\)\s*values\s*\((.*)\)", n)
        assert match is not None, n
        columns = [c.strip() for c in match.group(1).split(",")]
        values = [v.strip() for v in match.group(2).split(",")]
        row: dict[str, Any] = {}
        for column, value in zip(columns, values, strict=True):
            placeholder = re.fullmatch(r"\$(\d+)(?:\s*::\s*\w+)?", value)
            assert placeholder is not None, value
            row[column] = args[int(placeholder.group(1)) - 1]
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
                "params": json.loads(params_json),
            }
        )
        return uuid.uuid4()

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
                    "org_status": account["org_status"],
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

    def _revoke(self, n: str, args: tuple[Any, ...]) -> str:
        now = datetime.now(UTC)
        if re.search(r"\bwhere\b.*\buser_id\b", n):
            user_id = plain(next(arg for arg in args if isinstance(arg, uuid.UUID)))
            count = 0
            for session in self.sessions.values():
                if session["user_id"] == user_id and session["revoked_at"] is None:
                    session["revoked_at"] = now
                    count += 1
            return f"UPDATE {count}"
        token_hash = next(arg for arg in args if isinstance(arg, bytes))
        session = self.sessions.get(token_hash)
        if session is None or session["revoked_at"] is not None:
            return "UPDATE 0"
        session["revoked_at"] = now
        return "UPDATE 1"

    def _session_row(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        token_hash = next((arg for arg in args if isinstance(arg, bytes)), None)
        session = self.sessions.get(token_hash) if token_hash is not None else None
        if session is None:
            return None
        account = self.users[session["user_id"]]
        return {
            "session_id": _pg(session["session_id"]),
            "revoked_at": session["revoked_at"],
            "expires_at": session["expires_at"],
            "user_id": _pg(account["id"]),
            "kind": account["kind"],
            "org_id": _pg(account["org_id"]),
            "role": account["role"],
            "status": account["status"],
            "deleted_at": account["deleted_at"],
            "org_status": account["org_status"],
            "ui_language": account["ui_language"],
            "response_language": account["response_language"],
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
                }
        return None


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
