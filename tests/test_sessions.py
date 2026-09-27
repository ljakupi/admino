"""Tests for admino.sessions — server-side sessions and the one Principal builder (GH-149).

A login creates a ``sessions`` row holding the SHA-256 hash of a random 256-bit
token; the raw token only ever lives in the ``admino_session`` cookie. Every
request resolves the cookie back to its session, re-reading the user's row, and
builds the ``Principal`` from that row (never from request data).

What these tests pin down:
- Tokens: ``secrets.token_urlsafe(32)`` values (43 URL-safe characters, 256 bits),
  unique; ``hash_session_token`` is the raw SHA-256 digest.
- ``create_session``: one parameterized INSERT carrying the token hash (never the
  raw token), the user id, ``expires_at = now + 12 h``, the client IP (NULL when
  it isn't an IP address, e.g. "testclient") and the user agent truncated to 256
  characters.
- ``resolve_session``: a token that isn't a plausible ``token_urlsafe(32)`` value
  returns None without a query; otherwise one ``fetchrow`` by token hash, joining
  users and (LEFT JOIN) organizations. The decision is made in Python on every
  call: no row, revoked, expired, a user that isn't active or is deleted, or a
  member of an org that isn't active → None. An active member or Super Admin
  gets an ``AuthenticatedSession`` whose Principal comes from the row, with plain
  ``uuid.UUID`` IDs even when asyncpg returns its own UUID subclass.
- A deactivated user or org is rejected on an already-open session: the next
  resolve re-reads the row and returns None.
- ``revoke_session``: one parameterized UPDATE setting ``revoked_at``.

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- The raw token appears in no SQL text, no bind parameter and no log line.
- Values travel as bind parameters, never inside the SQL text.
- A row that fails Principal validation fails closed (None), never raises.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

from admino.access import Capability, Principal, SealedModel, can
from admino.sessions import (
    SESSION_COOKIE_NAME,
    SESSION_LIFETIME,
    USER_AGENT_MAX_LENGTH,
    AuthenticatedSession,
    create_session,
    hash_session_token,
    new_session_token,
    resolve_session,
    revoke_session,
)

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_USER_ID = uuid.UUID("5f0e8a3c-1d2b-4c6e-9a7f-0b1c2d3e4f50")
_ORG_ID = uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
_SESSION_ID = uuid.UUID("0c9b8a7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d")
_VALID_TOKEN = "Q" * 21 + "-" + "z" * 20 + "_"  # 43 URL-safe characters


def _norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


class _Executor:
    """A stand-in asyncpg executor that records every call.

    Each call is recorded as (method, sql, args). ``fetchrow`` returns the queued
    rows in order (None once exhausted); the other methods return fixed values.
    """

    def __init__(self, rows: list[dict[str, Any] | None] | None = None) -> None:
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        self._rows = list(rows or [])

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(("execute", sql, args))
        return "OK"

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        self.calls.append(("fetchrow", sql, args))
        return self._rows.pop(0) if self._rows else None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetchval", sql, args))
        return _SESSION_ID

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.calls.append(("fetch", sql, args))
        return []


def _insert_row(executor: _Executor) -> dict[str, Any]:
    """Map each column of the one INSERT INTO sessions to its bind argument."""
    inserts = [c for c in executor.calls if "insert into sessions" in _norm(c[1])]
    assert len(inserts) == 1, executor.calls
    _, sql, args = inserts[0]
    match = re.search(r"insert into sessions\s*\(([^)]*)\)\s*values\s*\((.*)\)", _norm(sql))
    assert match is not None, sql
    columns = [c.strip().strip('"') for c in match.group(1).split(",")]
    values = [v.strip() for v in match.group(2).split(",")]
    assert len(columns) == len(values), sql
    row: dict[str, Any] = {}
    for column, value in zip(columns, values, strict=True):
        placeholder = re.fullmatch(r"\$(\d+)(?:\s*::\s*\w+)?", value)
        assert placeholder is not None, f"{column} is not a bind parameter: {value}"
        row[column] = args[int(placeholder.group(1)) - 1]
    return row


def _row(**overrides: Any) -> dict[str, Any]:
    """A session row as resolve_session's query returns it: an active editor, asyncpg UUIDs."""
    now = datetime.now(UTC)
    row: dict[str, Any] = {
        "session_id": PgUUID(str(_SESSION_ID)),
        "revoked_at": None,
        "expires_at": now + timedelta(hours=11),
        "user_id": PgUUID(str(_USER_ID)),
        "kind": "member",
        "org_id": PgUUID(str(_ORG_ID)),
        "role": "editor",
        "status": "active",
        "deleted_at": None,
        "org_status": "active",
        "ui_language": "de",
        "response_language": "fr",
    }
    row.update(overrides)
    return row


def _super_admin_row(**overrides: Any) -> dict[str, Any]:
    """An active Super Admin's session row: no org, no role, no org status."""
    fields: dict[str, Any] = {
        "kind": "super_admin",
        "org_id": None,
        "role": None,
        "org_status": None,
        "ui_language": "en",
        "response_language": None,
    }
    fields.update(overrides)
    return _row(**fields)


def _all_args(executor: _Executor) -> list[Any]:
    """Every bind argument of every call."""
    return [arg for _, _, args in executor.calls for arg in args]


# ---------------------------------------------------------------------------
# 1. Constants and tokens
# ---------------------------------------------------------------------------


class TestSessionConstants:
    """The cookie name, lifetime and user-agent bound are the documented values."""

    def test_sessions_cookie_name(self) -> None:
        """The cookie is called admino_session."""
        assert SESSION_COOKIE_NAME == "admino_session"

    def test_sessions_lifetime_is_12_hours(self) -> None:
        """A session lives 12 hours (until #152 adds idle timeouts)."""
        assert timedelta(hours=12) == SESSION_LIFETIME

    def test_sessions_user_agent_bound(self) -> None:
        """User agents are stored truncated to 256 characters."""
        assert USER_AGENT_MAX_LENGTH == 256


class TestSessionTokens:
    """Tokens are 256-bit, URL-safe and unique; their hash is SHA-256."""

    def test_sessions_token_is_43_url_safe_characters(self) -> None:
        """token_urlsafe(32): 43 characters from [A-Za-z0-9_-]."""
        assert _TOKEN_RE.fullmatch(new_session_token()) is not None

    def test_sessions_token_carries_256_bits(self) -> None:
        """The token decodes to 32 random bytes."""
        token = new_session_token()

        assert len(base64.urlsafe_b64decode(token + "=")) == 32

    def test_sessions_tokens_are_unique(self) -> None:
        """1000 tokens, 1000 distinct values."""
        assert len({new_session_token() for _ in range(1000)}) == 1000

    def test_sessions_token_hash_is_sha256_digest(self) -> None:
        """hash_session_token is the raw 32-byte SHA-256 of the UTF-8 token."""
        token = new_session_token()

        assert hash_session_token(token) == hashlib.sha256(token.encode()).digest()

    def test_sessions_token_hash_is_32_bytes(self) -> None:
        """bytes, 32 long (the BYTEA CHECK in migration 0007)."""
        digest = hash_session_token(_VALID_TOKEN)

        assert isinstance(digest, bytes)
        assert len(digest) == 32

    def test_sessions_token_hash_differs_per_token(self) -> None:
        """Different tokens, different hashes; the same token, the same hash."""
        assert hash_session_token("a" * 43) != hash_session_token("b" * 43)
        assert hash_session_token(_VALID_TOKEN) == hash_session_token(_VALID_TOKEN)


# ---------------------------------------------------------------------------
# 2. create_session
# ---------------------------------------------------------------------------


async def _create(**overrides: Any) -> tuple[str, _Executor]:
    """Run create_session with defaults; return the token and the executor."""
    executor = _Executor()
    kwargs: dict[str, Any] = {
        "user_id": _USER_ID,
        "ip": "203.0.113.9",
        "user_agent": "Mozilla/5.0 (test)",
    }
    kwargs.update(overrides)
    token = await create_session(executor, **kwargs)
    return token, executor


class TestCreateSession:
    """create_session issues one parameterized INSERT and returns the raw token."""

    async def test_sessions_create_returns_a_url_safe_token(self) -> None:
        """The returned token is a token_urlsafe(32) value."""
        token, _ = await _create()

        assert _TOKEN_RE.fullmatch(token) is not None

    async def test_sessions_create_issues_exactly_one_insert(self) -> None:
        """One statement, and it is the INSERT INTO sessions."""
        _, executor = await _create()

        assert len(executor.calls) == 1
        assert "insert into sessions" in _norm(executor.calls[0][1])

    async def test_sessions_create_stores_the_token_hash(self) -> None:
        """token_hash is sha256(token), bound as a parameter."""
        token, executor = await _create()

        assert _insert_row(executor)["token_hash"] == hash_session_token(token)

    async def test_sessions_create_never_stores_the_raw_token(self) -> None:
        """The raw token is in no bind parameter and not in the SQL text."""
        token, executor = await _create()

        assert all(token not in str(arg) for arg in _all_args(executor))
        assert token not in executor.calls[0][1]

    async def test_sessions_create_binds_values_never_inlines_them(self) -> None:
        """The user id and the hash travel as bind parameters, not inside the SQL."""
        token, executor = await _create()
        sql = executor.calls[0][1]

        assert str(_USER_ID) not in sql
        assert hash_session_token(token).hex() not in sql
        assert "$1" in sql

    async def test_sessions_create_stores_the_user_id(self) -> None:
        """user_id is the account the session belongs to."""
        _, executor = await _create()

        assert _insert_row(executor)["user_id"] == _USER_ID

    async def test_sessions_create_expires_in_12_hours(self) -> None:
        """expires_at = now + SESSION_LIFETIME (a timezone-aware datetime)."""
        before = datetime.now(UTC)
        _, executor = await _create()
        after = datetime.now(UTC)

        expires_at = _insert_row(executor)["expires_at"]
        assert isinstance(expires_at, datetime)
        assert expires_at.tzinfo is not None
        assert before + timedelta(hours=12) - timedelta(seconds=5) <= expires_at
        assert expires_at <= after + timedelta(hours=12) + timedelta(seconds=5)

    @pytest.mark.parametrize("ip", ["203.0.113.9", "2001:db8::1", "10.0.0.1"])
    async def test_sessions_create_keeps_a_valid_ip(self, ip: str) -> None:
        """An IPv4 or IPv6 client address is stored."""
        _, executor = await _create(ip=ip)

        stored = _insert_row(executor)["ip"]
        assert stored is not None
        assert ip_address(str(stored)) == ip_address(ip)

    @pytest.mark.parametrize("ip", ["testclient", "not-an-ip", "", "999.1.1.1", None])
    async def test_sessions_create_stores_null_for_a_non_ip(self, ip: str | None) -> None:
        """A peer that isn't an IP address (e.g. TestClient's 'testclient') is NULL."""
        _, executor = await _create(ip=ip)

        assert _insert_row(executor)["ip"] is None

    async def test_sessions_create_truncates_the_user_agent(self) -> None:
        """A 300-character user agent is stored as its first 256 characters."""
        user_agent = "".join(chr(ord("a") + i % 26) for i in range(300))
        _, executor = await _create(user_agent=user_agent)

        assert _insert_row(executor)["user_agent"] == user_agent[:256]

    async def test_sessions_create_truncates_by_characters(self) -> None:
        """Truncation counts characters (the CHECK uses char_length), not bytes."""
        _, executor = await _create(user_agent="é" * 300)

        assert _insert_row(executor)["user_agent"] == "é" * 256

    @pytest.mark.parametrize("length", [0, 1, 255, 256])
    async def test_sessions_create_keeps_a_short_user_agent(self, length: int) -> None:
        """Up to 256 characters are stored unchanged."""
        user_agent = "u" * length
        _, executor = await _create(user_agent=user_agent)

        assert _insert_row(executor)["user_agent"] == user_agent

    async def test_sessions_create_keeps_a_missing_user_agent_null(self) -> None:
        """No user agent → NULL."""
        _, executor = await _create(user_agent=None)

        assert _insert_row(executor)["user_agent"] is None

    async def test_sessions_create_returns_a_new_token_each_call(self) -> None:
        """Two sessions for the same user get different tokens and hashes."""
        first, first_executor = await _create()
        second, second_executor = await _create()

        assert first != second
        assert (
            _insert_row(first_executor)["token_hash"] != _insert_row(second_executor)["token_hash"]
        )

    async def test_sessions_create_never_logs_the_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No log line (at any level) carries the raw token."""
        caplog.set_level(logging.DEBUG)

        token, _ = await _create()

        assert token not in caplog.text

    def test_sessions_create_takes_keyword_only_values(self) -> None:
        """create_session(executor, *, user_id, ip, user_agent)."""
        params = list(inspect.signature(create_session).parameters.values())

        assert [p.name for p in params] == ["executor", "user_id", "ip", "user_agent"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])


# ---------------------------------------------------------------------------
# 3. resolve_session — shape of the lookup
# ---------------------------------------------------------------------------

_MALFORMED_TOKENS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("short", id="short"),
    pytest.param("a" * 42, id="42-chars"),
    pytest.param("a" * 44, id="44-chars"),
    pytest.param("a" * 42 + "=", id="padding"),
    pytest.param("a" * 42 + "+", id="plus"),
    pytest.param("a" * 42 + "/", id="slash"),
    pytest.param("a" * 42 + ".", id="dot"),
    pytest.param("a" * 43 + "\n", id="trailing-newline"),
    pytest.param(" " + "a" * 42, id="leading-space"),
    pytest.param("a" * 42 + " ", id="trailing-space"),
    pytest.param("é" * 43, id="non-ascii"),
    pytest.param("a" * 20 + "'" + "a" * 22, id="quote"),
    pytest.param("a" * 10_000, id="huge"),
]


class TestResolveSessionLookup:
    """One parameterized fetchrow by token hash; malformed tokens never reach the DB."""

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_sessions_resolve_malformed_token_returns_none_without_query(
        self, token: str
    ) -> None:
        """Anything that isn't ^[A-Za-z0-9_-]{43}$ returns None and issues no query."""
        executor = _Executor([_row()])

        assert await resolve_session(executor, token) is None
        assert executor.calls == []

    async def test_sessions_resolve_issues_one_fetchrow(self) -> None:
        """A well-formed token costs exactly one fetchrow."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    async def test_sessions_resolve_looks_up_by_token_hash(self) -> None:
        """The token's SHA-256 digest is a bind parameter; the raw token is not."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        _, sql, args = executor.calls[0]
        assert hash_session_token(_VALID_TOKEN) in args
        assert all(_VALID_TOKEN not in str(arg) for arg in args)
        assert _VALID_TOKEN not in sql
        assert hash_session_token(_VALID_TOKEN).hex() not in sql

    async def test_sessions_resolve_joins_users_and_left_joins_organizations(self) -> None:
        """The session, its users row and (LEFT JOIN: Super Admins have none) its org."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        sql = _norm(executor.calls[0][1])
        assert re.search(r"\bfrom sessions\b", sql) is not None
        assert re.search(r"\bjoin users\b", sql) is not None
        assert re.search(r"\bleft (?:outer )?join organizations\b", sql) is not None

    async def test_sessions_resolve_unknown_token_returns_none(self) -> None:
        """No row → None."""
        assert await resolve_session(_Executor([None]), _VALID_TOKEN) is None

    def test_sessions_resolve_takes_only_the_executor_and_token(self) -> None:
        """Nothing from the request (body, headers, claimed role) can reach the Principal."""
        assert list(inspect.signature(resolve_session).parameters) == ["executor", "token"]

    async def test_sessions_resolve_never_logs_the_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No log line carries the raw token, found or not."""
        caplog.set_level(logging.DEBUG)

        await resolve_session(_Executor([_row()]), _VALID_TOKEN)
        await resolve_session(_Executor([None]), _VALID_TOKEN)

        assert _VALID_TOKEN not in caplog.text


# ---------------------------------------------------------------------------
# 4. resolve_session — the decision (re-made in Python on every call)
# ---------------------------------------------------------------------------

_REJECTED_ROWS: list[Any] = [
    pytest.param(_row(revoked_at=datetime.now(UTC) - timedelta(minutes=5)), id="revoked"),
    pytest.param(_row(expires_at=datetime.now(UTC) - timedelta(seconds=1)), id="expired"),
    pytest.param(_row(expires_at=datetime.now(UTC) - timedelta(days=30)), id="long-expired"),
    pytest.param(_row(status="deactivated"), id="user-deactivated"),
    pytest.param(_row(status="invited"), id="user-invited"),
    pytest.param(_row(status="unknown"), id="user-status-unknown"),
    pytest.param(_row(deleted_at=datetime.now(UTC) - timedelta(days=1)), id="user-deleted"),
    pytest.param(_row(org_status="deactivated"), id="org-deactivated"),
    pytest.param(_row(org_status="pending_deletion"), id="org-pending-deletion"),
    pytest.param(_row(org_status=None), id="member-org-missing"),
    pytest.param(_super_admin_row(status="deactivated"), id="super-admin-deactivated"),
    pytest.param(
        _super_admin_row(deleted_at=datetime.now(UTC) - timedelta(days=1)),
        id="super-admin-deleted",
    ),
]

# Rows whose account fields can't form a valid Principal: fail closed.
_INVALID_PRINCIPAL_ROWS: list[Any] = [
    pytest.param(_row(org_id=None), id="member-without-org"),
    pytest.param(_row(role=None), id="member-without-role"),
    pytest.param(_row(role="owner"), id="member-unknown-role"),
    pytest.param(_row(kind="root"), id="unknown-kind"),
    pytest.param(_super_admin_row(role="org_admin"), id="super-admin-with-role"),
    pytest.param(
        _super_admin_row(org_id=PgUUID(str(_ORG_ID)), org_status="active"),
        id="super-admin-with-org",
    ),
]


class TestResolveSessionRejects:
    """Every non-usable session resolves to None."""

    @pytest.mark.parametrize("row", _REJECTED_ROWS)
    async def test_sessions_resolve_rejects(self, row: dict[str, Any]) -> None:
        """Revoked, expired, inactive or deleted user, inactive org → None."""
        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None

    @pytest.mark.parametrize("row", _INVALID_PRINCIPAL_ROWS)
    async def test_sessions_resolve_invalid_principal_row_fails_closed(
        self, row: dict[str, Any]
    ) -> None:
        """A row that fails Principal validation returns None instead of raising."""
        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None


class TestResolveSessionAccepts:
    """An active member or Super Admin gets an AuthenticatedSession built from the row."""

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_sessions_resolve_active_member(self, role: str) -> None:
        """The Principal is the row's user, kind, org and role."""
        session = await resolve_session(_Executor([_row(role=role)]), _VALID_TOKEN)

        assert session is not None
        assert session.principal == Principal(
            user_id=_USER_ID, kind="member", org_id=_ORG_ID, role=role
        )

    async def test_sessions_resolve_carries_session_id_and_languages(self) -> None:
        """session_id, ui_language and response_language come from the row."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert session is not None
        assert session.session_id == _SESSION_ID
        assert (session.ui_language, session.response_language) == ("de", "fr")

    async def test_sessions_resolve_active_super_admin(self) -> None:
        """A Super Admin (no org, LEFT JOIN gives no org status) resolves: no org, no role."""
        session = await resolve_session(_Executor([_super_admin_row()]), _VALID_TOKEN)

        assert session is not None
        assert session.principal == Principal(user_id=_USER_ID, kind="super_admin")
        assert (session.ui_language, session.response_language) == ("en", None)

    async def test_sessions_resolve_returns_an_authenticated_session(self) -> None:
        """The result is an AuthenticatedSession (a SealedModel) with an exact Principal."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert type(session) is AuthenticatedSession
        assert type(session.principal) is Principal

    async def test_sessions_resolve_principal_ids_are_plain_uuids(self) -> None:
        """asyncpg's UUID subclass never reaches the Principal: plain uuid.UUID fields."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert session is not None
        assert type(session.principal.user_id) is uuid.UUID
        assert type(session.principal.org_id) is uuid.UUID

    @pytest.mark.parametrize(
        ("role", "allowed"), [("org_admin", True), ("editor", True), ("viewer", False)]
    )
    async def test_sessions_resolve_principal_passes_can_for_its_role(
        self, role: str, allowed: bool
    ) -> None:
        """A member built from asyncpg UUIDs gets its role's capabilities (the #145 bug)."""
        session = await resolve_session(_Executor([_row(role=role)]), _VALID_TOKEN)

        assert session is not None
        assert can(session.principal, Capability.CHAT_SEND) is allowed
        assert can(session.principal, Capability.ACCOUNT_MANAGE) is True

    async def test_sessions_resolve_super_admin_passes_can(self) -> None:
        """The Super Admin keeps its platform capabilities and gets no content ones."""
        session = await resolve_session(_Executor([_super_admin_row()]), _VALID_TOKEN)

        assert session is not None
        assert can(session.principal, Capability.ORG_CREATE) is True
        assert can(session.principal, Capability.CHAT_SEND) is False

    async def test_sessions_resolve_session_is_sealed(self) -> None:
        """AuthenticatedSession is a SealedModel: frozen, no unvalidated construction."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert isinstance(session, SealedModel)
        with pytest.raises(TypeError):
            AuthenticatedSession.model_construct(
                session_id=_SESSION_ID,
                principal=Principal(user_id=_USER_ID, kind="super_admin"),
                ui_language="en",
                response_language=None,
            )


# ---------------------------------------------------------------------------
# 5. An already-open session is rejected once the user or org is deactivated
# ---------------------------------------------------------------------------


class TestResolveSessionAlreadyOpen:
    """The users row is re-read on every call, so a deactivation takes effect at once."""

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"status": "deactivated"}, id="user-deactivated"),
            pytest.param({"deleted_at": datetime.now(UTC)}, id="user-deleted"),
            pytest.param({"org_status": "deactivated"}, id="org-deactivated"),
            pytest.param({"org_status": "pending_deletion"}, id="org-pending-deletion"),
            pytest.param({"revoked_at": datetime.now(UTC)}, id="session-revoked"),
        ],
    )
    async def test_sessions_open_session_rejected_after_change(
        self, change: dict[str, Any]
    ) -> None:
        """The same token resolves, then the re-read row shows the change → None."""
        executor = _Executor([_row(), _row(**change)])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is None
        assert [method for method, _, _ in executor.calls] == ["fetchrow", "fetchrow"]

    async def test_sessions_role_change_takes_effect_on_the_next_request(self) -> None:
        """A demotion (editor → viewer) shows on the next resolve: nothing is cached."""
        executor = _Executor([_row(role="editor"), _row(role="viewer")])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is not None
        assert (first.principal.role, second.principal.role) == ("editor", "viewer")


# ---------------------------------------------------------------------------
# 6. revoke_session
# ---------------------------------------------------------------------------


class TestRevokeSession:
    """revoke_session sets revoked_at through one parameterized UPDATE."""

    async def test_sessions_revoke_issues_one_update(self) -> None:
        """UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL."""
        executor = _Executor()

        result = await revoke_session(executor, _VALID_TOKEN)

        assert result is None
        assert len(executor.calls) == 1
        sql = _norm(executor.calls[0][1])
        assert sql.startswith("update sessions set revoked_at = now()")
        assert re.search(r"\btoken_hash = \$1\b", sql) is not None
        assert "revoked_at is null" in sql

    async def test_sessions_revoke_binds_the_token_hash(self) -> None:
        """The hash is the bind parameter; the raw token appears nowhere."""
        executor = _Executor()

        await revoke_session(executor, _VALID_TOKEN)

        _, sql, args = executor.calls[0]
        assert args == (hash_session_token(_VALID_TOKEN),)
        assert _VALID_TOKEN not in sql

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_sessions_revoke_malformed_token_issues_no_query(self, token: str) -> None:
        """A token that can't exist is ignored without touching the database."""
        executor = _Executor()

        await revoke_session(executor, token)

        assert executor.calls == []
