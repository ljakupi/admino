"""Shared in-memory database for the service and HTTP tests (GH-151, GH-152).

``FakeDb`` stands in for the users, organizations, sessions,
password_reset_tokens, email_outbox and audit_events tables behind a
pool-shaped object (``FakeDb.pool``). The real ``admino.auth``,
``admino.sessions``, ``admino.session_management``, ``admino.password_reset``,
``admino.email_outbox`` and ``admino.audit_events`` code runs against it: each
statement is recognised by its table and verb, and its bind parameters are
applied to the in-memory tables, so a test can log in, list and revoke
sessions, request and confirm a password reset, and check the result.

Inputs: accounts and sessions added with ``add_account`` / ``open_session``.
Outputs: the recorded calls (``calls``: method, SQL, args, which pool or
connection ran it and inside which transaction), the table state, and the
outcome of every transaction (``transactions``: commit or rollback).

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
        org_id: uuid.UUID = ORG_ID,
    ) -> uuid.UUID:
        """Add an account and return its id (a plain uuid.UUID)."""
        user_id = uuid.uuid4()
        is_member = kind == "member"
        self.users[user_id] = {
            "id": user_id,
            "email": email or f"user-{user_id.hex[:8]}@example.test",
            "name": "Some Person",
            "kind": kind,
            "org_id": org_id if is_member else None,
            "role": role if is_member else None,
            "status": status,
            "deleted_at": deleted_at,
            "password_hash": password_hash,
            "org_status": org_status if is_member else None,
            "ui_language": ui_language,
            "response_language": None,
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
        if re.search(r"\brevoked_at\b", n):
            # Migration 0009 dropped the column: revoking deletes the row.
            raise asyncpg.exceptions.UndefinedColumnError('column "revoked_at" does not exist')
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
            "org_status": account["org_status"],
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
