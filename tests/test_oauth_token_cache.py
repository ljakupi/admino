"""Tests for per-user OAuth persistence and the per-user access-token cache (GH-162).

GH-162 re-keys ``oauth_tokens`` to ``(user_id, provider)``: every user connects
their own Google and Microsoft accounts. ``admino.oauth``'s persistence functions
take the caller's ``TenantContext`` and only ever read or write that user's row in
that org. One process-wide ``AccessTokenCache`` keyed by ``(user_id, provider)``
replaces the six tool modules' module-level access-token caches.

What these tests pin down (the GH-162 contract, section 6):
- Persistence, run against tests/db_fakes.FakeDb (migration 0017's oauth_tokens:
  primary key (user_id, provider), FKs to users and organizations):
  ``save_token`` upserts the tenant's own row (another user's or provider's row
  never changes, created_at is kept); ``load_token`` returns only the tenant's
  row (a colleague, a user of another org or the right user with the wrong org
  sees nothing); ``delete_token`` deletes only the tenant's row and reports
  whether it did; ``get_connection_status`` is per tenant; and
  ``revoke_and_delete_token`` revokes and deletes the caller's row only.
- Every statement on oauth_tokens is parameterized and binds both the tenant's
  user_id and org_id (never another user's id, never an id in the SQL text).
- Fernet at rest: the stored column decrypts with ``OAUTH_ENCRYPTION_KEY`` to
  the plaintext; neither the plaintext refresh token nor an access token ever
  reaches a column or a bound argument.
- ``get_valid_access_token`` refreshes with the tenant's own refresh token (A's,
  never B's) and a terminal ``invalid_grant`` flips ``healthy`` on the tenant's
  row only.
- ``AccessTokenCache`` / ``access_tokens`` / ``ACCESS_TOKEN_CACHE_MAX`` (512):
  ``get`` calls the module-level ``get_valid_access_token`` (patched here) with
  the key's cached token and expiry and caches the result; keys are
  (user_id, provider); one lock per key (one refresh at a time per key, different
  keys concurrently: a blocked refresh of A never delays B, and 20 users at once
  each get their own token over many interleavings); bounded LRU; ``invalidate``
  drops one key, also against an in-flight refresh; errors propagate and cache
  nothing; ``clear()`` empties; nothing logs a token or a user id.

``AccessTokenCache``, ``access_tokens`` and ``ACCESS_TOKEN_CACHE_MAX`` are read
through the module (``oauth.AccessTokenCache``), so each test fails on its own
until they exist.

Security notes:
- Tenant isolation: user A's refresh token, access token and row are never
  used, returned or changed for user B, including under concurrent requests.
- No network: every httpx client is an AsyncMock; the cache tests patch
  ``admino.oauth.get_valid_access_token``.
- Secrets are generated per test (``secrets``); nothing here is a real secret.
- Concurrency tests wait with ``asyncio.wait_for`` timeouts, so an
  implementation that serializes every user behind one lock fails instead of
  hanging.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import secrets
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet

import admino.oauth as oauth
from admino.access import Principal
from admino.oauth import OAuthError, OAuthRefreshError, OAuthToken, encrypt_refresh_token
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from admino.access import MemberRole
    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------

_FERNET_KEY: str = Fernet.generate_key().decode()
_PROVIDERS: tuple[str, str] = ("google", "microsoft")
# How long any concurrency step may take before the test fails instead of hanging.
_WAIT: float = 5.0
# Stand-ins for the pool and the client in the cache tests (get_valid_access_token is patched).
_POOL: Any = object()

_Key = tuple[uuid.UUID, str]


@pytest.fixture()
def oauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The encryption key and both providers' client credentials."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", _FERNET_KEY)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "gh162-google-client-id.apps.example")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "gh162-google-client-secret")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "gh162-microsoft-client-id")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "gh162-microsoft-client-secret")


@pytest.fixture(autouse=True)
def _empty_process_cache() -> Iterator[None]:
    """Keep the process-wide cache empty around every test (once it exists)."""
    cache = getattr(oauth, "access_tokens", None)
    if cache is not None:
        cache.clear()
    yield
    cache = getattr(oauth, "access_tokens", None)
    if cache is not None:
        cache.clear()


def _tenant(
    user_id: uuid.UUID, org_id: uuid.UUID = ORG_ID, role: MemberRole = "editor"
) -> TenantContext:
    """The TenantContext a resolved session of this member would carry."""
    return TenantContext.from_principal(
        Principal(user_id=user_id, kind="member", org_id=org_id, role=role)
    )


@dataclass(frozen=True)
class _World:
    """Three stored members: A and B in ORG_ID, C in OTHER_ORG_ID, and their tenants."""

    db: FakeDb
    a: uuid.UUID
    b: uuid.UUID
    c: uuid.UUID
    ta: TenantContext
    tb: TenantContext
    tc: TenantContext
    # A's user id with another org's id: what a request value must never be able to reach.
    ta_other_org: TenantContext


@pytest.fixture()
def world(oauth_env: None) -> _World:
    """A FakeDb with users A (editor) and B (org admin) in one org and C in another."""
    _ = oauth_env
    db = FakeDb()
    a = db.add_account(role="editor")
    b = db.add_account(role="org_admin")
    c = db.add_account(role="editor", org_id=OTHER_ORG_ID)
    return _World(
        db=db,
        a=a,
        b=b,
        c=c,
        ta=_tenant(a),
        tb=_tenant(b, role="org_admin"),
        tc=_tenant(c, OTHER_ORG_ID),
        ta_other_org=_tenant(a, OTHER_ORG_ID),
    )


def _plain(label: str) -> str:
    """A fresh plaintext refresh token for one user."""
    return f"1//{label}-refresh-{secrets.token_urlsafe(18)}"


def _access_for(refresh_token: str) -> str:
    """The access token the mocked token endpoint issues for a refresh token."""
    return "ya29." + hashlib.sha256(refresh_token.encode()).hexdigest()[:32]


def _token(
    provider: str,
    plaintext: str,
    *,
    email: str | None = None,
    healthy: bool = True,
    created_at: datetime | None = None,
) -> OAuthToken:
    """An OAuthToken holding the Fernet ciphertext of ``plaintext``."""
    now = datetime.now(UTC)
    return OAuthToken(
        provider=provider,
        scopes=[f"{provider}.scope.read", f"{provider}.scope.write"],
        encrypted_refresh_token=encrypt_refresh_token(plaintext),
        email=email,
        healthy=healthy,
        created_at=created_at or now,
        last_refreshed_at=now,
    )


def _seed(db: FakeDb, user_id: uuid.UUID, provider: str, plaintext: str, **fields: Any) -> None:
    """Store a user's row directly in the fake (no statement is recorded)."""
    db.add_oauth_token(
        user_id, provider, encrypted_refresh_token=encrypt_refresh_token(plaintext), **fields
    )


def _refresh_client() -> AsyncMock:
    """A mocked httpx client: refreshes succeed, revocations and logouts return 200."""
    client = AsyncMock(spec=httpx.AsyncClient)

    async def _post(url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        _ = url, args
        data = kwargs.get("data") or {}
        refresh_token = data.get("refresh_token")
        if refresh_token is None:
            return httpx.Response(200, json={})
        return httpx.Response(
            200, json={"access_token": _access_for(refresh_token), "expires_in": 3600}
        )

    client.post.side_effect = _post
    client.get.return_value = httpx.Response(200, json={})
    return client


def _invalid_grant_client() -> AsyncMock:
    """A mocked httpx client whose token endpoint answers a terminal invalid_grant."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.post.return_value = httpx.Response(400, json={"error": "invalid_grant"})
    client.get.return_value = httpx.Response(200, json={})
    return client


def _posted(client: AsyncMock, field: str) -> list[str]:
    """Every value of a form field the client POSTed (refresh_token, or token for revocation)."""
    values: list[str] = []
    for call in client.post.call_args_list:
        data = call.kwargs.get("data") or {}
        if field in data:
            values.append(data[field])
    return values


def _row(db: FakeDb, user_id: uuid.UUID, provider: str) -> dict[str, Any]:
    """A stored oauth_tokens row that must exist."""
    row = db.oauth_token(user_id, provider)
    assert row is not None, f"no {provider} row for the user"
    return row


def _decrypt(ciphertext: str) -> str:
    return Fernet(_FERNET_KEY.encode()).decrypt(ciphertext.encode()).decode()


def _bound(call: Call, value: uuid.UUID) -> bool:
    """True when the statement binds this id (as a UUID or its string)."""
    for arg in call.args:
        if isinstance(arg, uuid.UUID) and plain(arg) == value:
            return True
        if isinstance(arg, str) and arg == str(value):
            return True
    return False


def _token_calls(db: FakeDb) -> list[Call]:
    return db.matching(r"\boauth_tokens\b")


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the captured records carry: messages, args, extras and tracebacks."""
    parts = [caplog.text]
    for record in caplog.records:
        parts.append(record.getMessage())
        parts.append(repr(record.args))
        parts.append(repr(vars(record)))
    return "\n".join(parts)


def _shuffled[T](items: list[T], seed: int) -> list[T]:
    """A deterministic permutation of ``items`` for one interleaving seed."""
    order = sorted(range(len(items)), key=lambda i: ((i * 37 + seed * 101) % 89, i))
    return [items[i] for i in order]


# ---------------------------------------------------------------------------
# The stand-in for get_valid_access_token in the cache tests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RefreshCall:
    """One call the cache made to get_valid_access_token, by parameter name."""

    pool: Any
    tenant: TenantContext
    provider: str
    cached_token: str | None
    cached_expires_at: datetime | None
    http_client: Any


class _FakeRefresher:
    """Stands in for ``oauth.get_valid_access_token`` (``refresh`` has its exact signature).

    A cached token passed back in is returned as it is (still valid); without one,
    a new token is minted for the tenant's (user_id, provider). Tests can block a
    key on a gate, make it fail, add scheduling yields, or hold every call at a
    barrier. It records how many calls ran at once, per key and in total.
    """

    def __init__(self) -> None:
        self.calls: list[_RefreshCall] = []
        self.minted: dict[_Key, list[str]] = defaultdict(list)
        self.entered: dict[_Key, asyncio.Event] = defaultdict(asyncio.Event)
        self.gates: dict[_Key, asyncio.Event] = {}
        self.errors: dict[_Key, Callable[[], Exception]] = {}
        self.yields: dict[_Key, int] = {}
        self.barrier: asyncio.Barrier | None = None
        self.in_flight: Counter[_Key] = Counter()
        self.max_in_flight: Counter[_Key] = Counter()
        self.total_in_flight = 0
        self.max_total_in_flight = 0

    async def refresh(
        self,
        pool: Any,
        tenant: TenantContext,
        provider: str,
        cached_token: str | None,
        cached_expires_at: datetime | None,
        http_client: Any,
    ) -> tuple[str, datetime]:
        key = (tenant.user_id, provider)
        self.calls.append(
            _RefreshCall(pool, tenant, provider, cached_token, cached_expires_at, http_client)
        )
        self.in_flight[key] += 1
        self.total_in_flight += 1
        self.max_in_flight[key] = max(self.max_in_flight[key], self.in_flight[key])
        self.max_total_in_flight = max(self.max_total_in_flight, self.total_in_flight)
        try:
            self.entered[key].set()
            if self.barrier is not None:
                await asyncio.wait_for(self.barrier.wait(), _WAIT)
            gate = self.gates.get(key)
            if gate is not None:
                await asyncio.wait_for(gate.wait(), _WAIT)
            for _ in range(self.yields.get(key, 3)):
                await asyncio.sleep(0)
            error = self.errors.get(key)
            if error is not None:
                raise error()
            if cached_token is not None and cached_expires_at is not None:
                return cached_token, cached_expires_at
            token = f"ya29.{secrets.token_urlsafe(12)}.{provider}.{len(self.minted[key]) + 1}"
            self.minted[key].append(token)
            return token, datetime.now(UTC) + timedelta(hours=1)
        finally:
            self.in_flight[key] -= 1
            self.total_in_flight -= 1

    def calls_for(self, user_id: uuid.UUID, provider: str) -> list[_RefreshCall]:
        return [
            call
            for call in self.calls
            if call.tenant.user_id == user_id and call.provider == provider
        ]

    def last(self, user_id: uuid.UUID, provider: str) -> _RefreshCall:
        calls = self.calls_for(user_id, provider)
        assert calls, "get_valid_access_token was never called for this key"
        return calls[-1]


@pytest.fixture()
def refresher(monkeypatch: pytest.MonkeyPatch) -> _FakeRefresher:
    """Patch admino.oauth.get_valid_access_token with a recording stand-in."""
    fake = _FakeRefresher()
    monkeypatch.setattr(oauth, "get_valid_access_token", AsyncMock(side_effect=fake.refresh))
    return fake


@pytest.fixture()
def client() -> AsyncMock:
    """The http client the cache passes through (never used: the refresh is patched)."""
    return AsyncMock(spec=httpx.AsyncClient)


def _users(count: int) -> list[uuid.UUID]:
    return [uuid.uuid4() for _ in range(count)]


# ---------------------------------------------------------------------------
# 1. Per-user persistence: save_token / load_token
# ---------------------------------------------------------------------------


class TestPerUserSaveAndLoad:
    """Each user's row is their own: saved under the tenant's ids, loaded only by them."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_save_then_load_returns_each_users_own_row(self, world: _World) -> None:
        """A and B (same org) each save a Google token; each loads exactly their own."""
        token_a = _token("google", _plain("A"), email="a@example.test")
        token_b = _token("google", _plain("B"), email="b@example.test")
        await oauth.save_token(world.db.pool, world.ta, token_a)
        await oauth.save_token(world.db.pool, world.tb, token_b)

        loaded_a = await oauth.load_token(world.db.pool, world.ta, "google")
        loaded_b = await oauth.load_token(world.db.pool, world.tb, "google")

        assert loaded_a is not None
        assert loaded_b is not None
        assert loaded_a.encrypted_refresh_token == token_a.encrypted_refresh_token
        assert loaded_a.email == "a@example.test"
        assert loaded_b.encrypted_refresh_token == token_b.encrypted_refresh_token
        assert loaded_b.email == "b@example.test"

    async def test_oauth_save_stores_row_under_the_tenants_user_and_org(
        self, world: _World
    ) -> None:
        """The row is keyed by the tenant's user_id and carries the tenant's org_id."""
        token = _token("microsoft", _plain("A"), email="a@example.test")

        await oauth.save_token(world.db.pool, world.ta, token)

        row = _row(world.db, world.a, "microsoft")
        assert plain(row["user_id"]) == world.a
        assert plain(row["org_id"]) == ORG_ID
        assert row["provider"] == "microsoft"
        assert row["encrypted_refresh_token"] == token.encrypted_refresh_token
        assert row["email"] == "a@example.test"
        assert row["healthy"] is True
        assert world.db.oauth_token(world.b, "microsoft") is None

    async def test_oauth_load_colleague_without_row_never_sees_users_row(
        self, world: _World
    ) -> None:
        """B (same org, no row of their own) gets None, not A's connection."""
        await oauth.save_token(world.db.pool, world.ta, _token("google", _plain("A")))

        assert await oauth.load_token(world.db.pool, world.tb, "google") is None

    async def test_oauth_load_other_org_user_never_sees_row(self, world: _World) -> None:
        """C (another org) never sees A's row; C's own row is still C's."""
        await oauth.save_token(world.db.pool, world.ta, _token("google", _plain("A")))
        assert await oauth.load_token(world.db.pool, world.tc, "google") is None

        token_c = _token("google", _plain("C"))
        await oauth.save_token(world.db.pool, world.tc, token_c)
        loaded_c = await oauth.load_token(world.db.pool, world.tc, "google")

        assert loaded_c is not None
        assert loaded_c.encrypted_refresh_token == token_c.encrypted_refresh_token

    async def test_oauth_load_with_wrong_org_tenant_returns_none(self, world: _World) -> None:
        """A's user id paired with another org's id loads nothing (the org filter applies)."""
        _seed(world.db, world.a, "google", _plain("A"))

        assert await oauth.load_token(world.db.pool, world.ta_other_org, "google") is None

    async def test_oauth_load_other_provider_returns_none(self, world: _World) -> None:
        """A's Google row is not A's Microsoft connection."""
        _seed(world.db, world.a, "google", _plain("A"))

        assert await oauth.load_token(world.db.pool, world.ta, "microsoft") is None

    async def test_oauth_save_is_upsert_per_user_and_provider(self, world: _World) -> None:
        """A's second Google save replaces A's Google row only (B's and A's Microsoft stay)."""
        await oauth.save_token(world.db.pool, world.ta, _token("google", _plain("A1")))
        await oauth.save_token(world.db.pool, world.tb, _token("google", _plain("B")))
        await oauth.save_token(world.db.pool, world.ta, _token("microsoft", _plain("AM")))
        b_before = dict(_row(world.db, world.b, "google"))
        a_microsoft_before = dict(_row(world.db, world.a, "microsoft"))

        second = _token("google", _plain("A2"), email="a2@example.test", healthy=False)
        await oauth.save_token(world.db.pool, world.ta, second)

        row = _row(world.db, world.a, "google")
        assert row["encrypted_refresh_token"] == second.encrypted_refresh_token
        assert row["email"] == "a2@example.test"
        assert row["healthy"] is False
        assert _row(world.db, world.b, "google") == b_before
        assert _row(world.db, world.a, "microsoft") == a_microsoft_before
        assert len(world.db.oauth_tokens) == 3

    async def test_oauth_save_upsert_keeps_the_rows_created_at(self, world: _World) -> None:
        """The upsert updates the token fields, never the row's created_at."""
        first_created = datetime.now(UTC) - timedelta(days=10)
        await oauth.save_token(
            world.db.pool, world.ta, _token("google", _plain("A1"), created_at=first_created)
        )

        await oauth.save_token(world.db.pool, world.ta, _token("google", _plain("A2")))

        assert _row(world.db, world.a, "google")["created_at"] == first_created

    async def test_oauth_save_unknown_provider_raises_and_writes_nothing(
        self, world: _World
    ) -> None:
        """An unknown provider is refused before any statement (OAuthError, as today)."""
        token = _token("google", _plain("A")).model_copy(update={"provider": "github"})

        with pytest.raises(OAuthError):
            await oauth.save_token(world.db.pool, world.ta, token)

        assert world.db.oauth_tokens == {}
        assert _token_calls(world.db) == []


# ---------------------------------------------------------------------------
# 2. Per-user persistence: delete_token
# ---------------------------------------------------------------------------


class TestPerUserDelete:
    """delete_token removes the tenant's own row and nothing else."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_delete_removes_only_the_callers_row(self, world: _World) -> None:
        """Deleting A's Google row keeps B's Google row and A's Microsoft row."""
        _seed(world.db, world.a, "google", _plain("A"))
        _seed(world.db, world.a, "microsoft", _plain("AM"))
        _seed(world.db, world.b, "google", _plain("B"))
        _seed(world.db, world.c, "google", _plain("C"))

        deleted = await oauth.delete_token(world.db.pool, world.ta, "google")

        assert deleted is True
        assert world.db.oauth_token(world.a, "google") is None
        assert world.db.oauth_token(world.a, "microsoft") is not None
        assert world.db.oauth_token(world.b, "google") is not None
        assert world.db.oauth_token(world.c, "google") is not None

    async def test_oauth_delete_second_time_returns_false(self, world: _World) -> None:
        """Once A's row is gone, deleting it again reports False."""
        _seed(world.db, world.a, "google", _plain("A"))
        await oauth.delete_token(world.db.pool, world.ta, "google")

        assert await oauth.delete_token(world.db.pool, world.ta, "google") is False

    async def test_oauth_delete_user_without_row_returns_false_and_keeps_others(
        self, world: _World
    ) -> None:
        """B has no row: delete reports False and A's row stays."""
        _seed(world.db, world.a, "google", _plain("A"))

        deleted = await oauth.delete_token(world.db.pool, world.tb, "google")

        assert deleted is False
        assert world.db.oauth_token(world.a, "google") is not None

    async def test_oauth_delete_with_wrong_org_tenant_keeps_the_row(self, world: _World) -> None:
        """A's user id with another org's id deletes nothing (the org filter applies)."""
        _seed(world.db, world.a, "google", _plain("A"))

        deleted = await oauth.delete_token(world.db.pool, world.ta_other_org, "google")

        assert deleted is False
        assert world.db.oauth_token(world.a, "google") is not None


# ---------------------------------------------------------------------------
# 3. Per-user persistence: get_connection_status
# ---------------------------------------------------------------------------


class TestPerUserConnectionStatus:
    """(connected, healthy) is computed from the tenant's own row only."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_status_connected_user_is_connected_and_healthy(
        self, world: _World
    ) -> None:
        """A with a healthy row is (True, True)."""
        _seed(world.db, world.a, "google", _plain("A"))

        assert await oauth.get_connection_status(world.db.pool, world.ta, "google") == (
            True,
            True,
        )

    @pytest.mark.parametrize("who", ["colleague", "other_org", "wrong_org_tenant"])
    async def test_oauth_status_without_own_row_is_not_connected(
        self, world: _World, who: str
    ) -> None:
        """B (same org), C (other org) and A-with-the-wrong-org are (False, False)."""
        _seed(world.db, world.a, "google", _plain("A"))
        tenant = {
            "colleague": world.tb,
            "other_org": world.tc,
            "wrong_org_tenant": world.ta_other_org,
        }

        status = await oauth.get_connection_status(world.db.pool, tenant[who], "google")

        assert status == (False, False)

    async def test_oauth_status_unhealthy_row_is_connected_but_unhealthy(
        self, world: _World
    ) -> None:
        """A's healthy=False row is (True, False); B's healthy row stays (True, True)."""
        _seed(world.db, world.a, "google", _plain("A"), healthy=False)
        _seed(world.db, world.b, "google", _plain("B"))

        status_a = await oauth.get_connection_status(world.db.pool, world.ta, "google")
        status_b = await oauth.get_connection_status(world.db.pool, world.tb, "google")

        assert status_a == (True, False)
        assert status_b == (True, True)

    async def test_oauth_status_undecryptable_row_is_connected_but_unhealthy(
        self, world: _World
    ) -> None:
        """A row encrypted under another key is (True, False)."""
        foreign = Fernet(Fernet.generate_key()).encrypt(b"1//other-key-refresh").decode()
        world.db.add_oauth_token(world.a, "google", encrypted_refresh_token=foreign)

        status = await oauth.get_connection_status(world.db.pool, world.ta, "google")

        assert status == (True, False)


# ---------------------------------------------------------------------------
# 4. Per-user persistence: revoke_and_delete_token
# ---------------------------------------------------------------------------


class TestPerUserRevokeAndDelete:
    """Disconnecting revokes the caller's own refresh token and deletes only their row."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_revoke_google_posts_callers_token_and_deletes_only_their_row(
        self, world: _World
    ) -> None:
        """A's plaintext refresh token is revoked; B's row (and token) are untouched."""
        plain_a, plain_b = _plain("A"), _plain("B")
        _seed(world.db, world.a, "google", plain_a)
        _seed(world.db, world.b, "google", plain_b)
        client = _refresh_client()

        result = await oauth.revoke_and_delete_token(world.db.pool, world.ta, "google", client)

        assert result is True
        assert _posted(client, "token") == [plain_a]
        assert world.db.oauth_token(world.a, "google") is None
        assert _decrypt(_row(world.db, world.b, "google")["encrypted_refresh_token"]) == plain_b

    async def test_oauth_revoke_microsoft_deletes_only_callers_row(self, world: _World) -> None:
        """Disconnecting A's Microsoft account keeps B's and A's Google rows."""
        _seed(world.db, world.a, "microsoft", _plain("AM"))
        _seed(world.db, world.a, "google", _plain("AG"))
        _seed(world.db, world.b, "microsoft", _plain("BM"))

        result = await oauth.revoke_and_delete_token(
            world.db.pool, world.ta, "microsoft", _refresh_client()
        )

        assert result is True
        assert world.db.oauth_token(world.a, "microsoft") is None
        assert world.db.oauth_token(world.a, "google") is not None
        assert world.db.oauth_token(world.b, "microsoft") is not None

    async def test_oauth_revoke_without_own_row_returns_false_without_http(
        self, world: _World
    ) -> None:
        """B has no row: nothing is revoked (A's token is never sent) and A's row stays."""
        _seed(world.db, world.a, "google", _plain("A"))
        client = _refresh_client()

        result = await oauth.revoke_and_delete_token(world.db.pool, world.tb, "google", client)

        assert result is False
        client.post.assert_not_called()
        client.get.assert_not_called()
        assert world.db.oauth_token(world.a, "google") is not None

    async def test_oauth_revoke_with_wrong_org_tenant_returns_false_and_keeps_row(
        self, world: _World
    ) -> None:
        """A's user id with another org's id neither revokes nor deletes A's row."""
        _seed(world.db, world.a, "google", _plain("A"))
        client = _refresh_client()

        result = await oauth.revoke_and_delete_token(
            world.db.pool, world.ta_other_org, "google", client
        )

        assert result is False
        client.post.assert_not_called()
        assert world.db.oauth_token(world.a, "google") is not None


# ---------------------------------------------------------------------------
# 5. Every statement on oauth_tokens carries the tenant's user and org
# ---------------------------------------------------------------------------


class TestStatementsCarryTheTenant:
    """Parameterized SQL only, and every statement binds the caller's user_id and org_id."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_every_statement_binds_tenants_user_and_org(self, world: _World) -> None:
        """Save, load, status, refresh, terminal refresh, delete and revoke for A."""
        _seed(world.db, world.b, "google", _plain("B"))
        _seed(world.db, world.c, "google", _plain("C"))
        pool, ta = world.db.pool, world.ta

        await oauth.save_token(pool, ta, _token("google", _plain("A")))
        await oauth.load_token(pool, ta, "google")
        await oauth.get_connection_status(pool, ta, "google")
        await oauth.get_valid_access_token(pool, ta, "google", None, None, _refresh_client())
        with pytest.raises(OAuthRefreshError):
            await oauth.get_valid_access_token(
                pool, ta, "google", None, None, _invalid_grant_client()
            )
        await oauth.delete_token(pool, ta, "google")
        await oauth.save_token(pool, ta, _token("microsoft", _plain("AM")))
        await oauth.get_valid_access_token(pool, ta, "microsoft", None, None, _refresh_client())
        await oauth.revoke_and_delete_token(pool, ta, "microsoft", _refresh_client())

        calls = _token_calls(world.db)
        verbs = {call.normalized.split(" ", 1)[0] for call in calls}
        assert {"select", "insert", "delete"} <= verbs
        for call in calls:
            n = call.normalized
            assert "$1" in call.sql, n
            assert _bound(call, world.a), f"user_id not bound: {n}"
            assert _bound(call, ORG_ID), f"org_id not bound: {n}"
            assert not _bound(call, world.b), f"another user's id bound: {n}"
            assert not _bound(call, world.c), f"another user's id bound: {n}"
            assert not _bound(call, OTHER_ORG_ID), f"another org's id bound: {n}"
            for value in (world.a, ORG_ID):
                assert str(value) not in call.sql
                assert value.hex not in call.sql
            assert "'google'" not in n
            assert "'microsoft'" not in n
            assert any(arg in _PROVIDERS for arg in call.args), f"provider not bound: {n}"


# ---------------------------------------------------------------------------
# 6. Fernet at rest
# ---------------------------------------------------------------------------


class TestFernetAtRest:
    """Refresh tokens keep their Fernet encryption; plaintext never reaches the database."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_stored_refresh_token_decrypts_with_the_env_key(
        self, world: _World
    ) -> None:
        """The stored column decrypts with OAUTH_ENCRYPTION_KEY, also after a refresh re-save."""
        plain_a = _plain("A")
        await oauth.save_token(world.db.pool, world.ta, _token("google", plain_a))

        stored = _row(world.db, world.a, "google")["encrypted_refresh_token"]
        assert stored != plain_a
        assert _decrypt(stored) == plain_a

        await oauth.get_valid_access_token(
            world.db.pool, world.ta, "google", None, None, _refresh_client()
        )

        assert _decrypt(_row(world.db, world.a, "google")["encrypted_refresh_token"]) == plain_a

    async def test_oauth_plaintext_and_access_token_never_reach_a_column_or_argument(
        self, world: _World
    ) -> None:
        """No stored column, statement or bound argument holds the plaintext or an access token."""
        plain_a = _plain("A")
        pool, ta = world.db.pool, world.ta
        await oauth.save_token(pool, ta, _token("google", plain_a))
        await oauth.load_token(pool, ta, "google")
        await oauth.get_connection_status(pool, ta, "google")
        access, _ = await oauth.get_valid_access_token(
            pool, ta, "google", None, None, _refresh_client()
        )
        assert access == _access_for(plain_a)

        for row in world.db.oauth_tokens.values():
            for value in row.values():
                assert plain_a not in str(value)
                assert access not in str(value)
        assert world.db.calls, "no statement ran"
        for call in world.db.calls:
            assert plain_a not in call.sql
            assert access not in call.sql
            for arg in call.args:
                assert plain_a not in str(arg)
                assert access not in str(arg)


# ---------------------------------------------------------------------------
# 7. get_valid_access_token uses the tenant's own refresh token
# ---------------------------------------------------------------------------


class TestPerUserRefresh:
    """A refresh reads, posts and updates only the tenant's own connection."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_refresh_posts_the_tenants_own_refresh_token(
        self, world: _World, provider: str
    ) -> None:
        """A's refresh posts A's decrypted token (never B's or C's) and returns A's access token."""
        plain_a, plain_b, plain_c = _plain("A"), _plain("B"), _plain("C")
        _seed(world.db, world.b, provider, plain_b)
        _seed(world.db, world.a, provider, plain_a)
        _seed(world.db, world.c, provider, plain_c)
        client = _refresh_client()

        access_a, _ = await oauth.get_valid_access_token(
            world.db.pool, world.ta, provider, None, None, client
        )
        access_b, _ = await oauth.get_valid_access_token(
            world.db.pool, world.tb, provider, None, None, client
        )

        assert _posted(client, "refresh_token") == [plain_a, plain_b]
        assert access_a == _access_for(plain_a)
        assert access_b == _access_for(plain_b)

    async def test_oauth_refresh_without_own_row_raises_even_when_colleague_connected(
        self, world: _World
    ) -> None:
        """B has no Google row: 'not connected', and A's token is never posted."""
        _seed(world.db, world.a, "google", _plain("A"))
        client = _refresh_client()

        with pytest.raises(OAuthError, match="No google account is connected"):
            await oauth.get_valid_access_token(
                world.db.pool, world.tb, "google", None, None, client
            )

        client.post.assert_not_called()

    async def test_oauth_refresh_with_wrong_org_tenant_raises_without_http(
        self, world: _World
    ) -> None:
        """A's user id with another org's id finds no connection."""
        _seed(world.db, world.a, "google", _plain("A"))
        client = _refresh_client()

        with pytest.raises(OAuthError, match="No google account is connected"):
            await oauth.get_valid_access_token(
                world.db.pool, world.ta_other_org, "google", None, None, client
            )

        client.post.assert_not_called()

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_terminal_invalid_grant_marks_only_the_tenants_row_unhealthy(
        self, world: _World, provider: str
    ) -> None:
        """invalid_grant flips healthy on A's row; B's, C's and A's other provider stay True."""
        other = "microsoft" if provider == "google" else "google"
        plain_a = _plain("A")
        _seed(world.db, world.a, provider, plain_a)
        _seed(world.db, world.a, other, _plain("A-other"))
        _seed(world.db, world.b, provider, _plain("B"))
        _seed(world.db, world.c, provider, _plain("C"))
        client = _invalid_grant_client()

        with pytest.raises(OAuthRefreshError) as exc_info:
            await oauth.get_valid_access_token(
                world.db.pool, world.ta, provider, None, None, client
            )

        assert exc_info.value.terminal is True
        assert _posted(client, "refresh_token") == [plain_a]
        assert _row(world.db, world.a, provider)["healthy"] is False
        assert _row(world.db, world.a, other)["healthy"] is True
        assert _row(world.db, world.b, provider)["healthy"] is True
        assert _row(world.db, world.c, provider)["healthy"] is True

    async def test_oauth_successful_refresh_recovers_only_the_tenants_row(
        self, world: _World
    ) -> None:
        """A successful refresh sets A's row healthy and fresh; B's unhealthy row is untouched."""
        old = datetime.now(UTC) - timedelta(days=3)
        _seed(world.db, world.a, "google", _plain("A"), healthy=False, last_refreshed_at=old)
        _seed(world.db, world.b, "google", _plain("B"), healthy=False, last_refreshed_at=old)
        b_before = dict(_row(world.db, world.b, "google"))

        await oauth.get_valid_access_token(
            world.db.pool, world.ta, "google", None, None, _refresh_client()
        )

        row_a = _row(world.db, world.a, "google")
        assert row_a["healthy"] is True
        assert row_a["last_refreshed_at"] > old
        assert _row(world.db, world.b, "google") == b_before


# ---------------------------------------------------------------------------
# 8. AccessTokenCache: surface
# ---------------------------------------------------------------------------


class TestAccessTokenCacheSurface:
    """The constant, the class's default bound and the process-wide instance."""

    def test_oauth_access_token_cache_max_is_512(self) -> None:
        """ACCESS_TOKEN_CACHE_MAX is 512 entries."""
        assert oauth.ACCESS_TOKEN_CACHE_MAX == 512

    def test_oauth_access_token_cache_default_bound_is_the_max(self) -> None:
        """AccessTokenCache(max_entries=ACCESS_TOKEN_CACHE_MAX) is the default."""
        parameters = inspect.signature(oauth.AccessTokenCache).parameters
        assert parameters["max_entries"].default == oauth.ACCESS_TOKEN_CACHE_MAX

    def test_oauth_access_tokens_is_the_process_wide_cache(self) -> None:
        """access_tokens is an AccessTokenCache."""
        assert isinstance(oauth.access_tokens, oauth.AccessTokenCache)

    @pytest.mark.parametrize("which", ["new_default_cache", "access_tokens"])
    async def test_oauth_default_cache_holds_at_most_512_keys(
        self, refresher: _FakeRefresher, client: AsyncMock, which: str
    ) -> None:
        """513 users: the cache keeps 512 and the first (least recently used) is evicted."""
        cache = oauth.AccessTokenCache() if which == "new_default_cache" else oauth.access_tokens
        users = _users(513)

        for user in users:
            await cache.get(_POOL, _tenant(user), "google", client)

        assert len(cache) == 512
        await cache.get(_POOL, _tenant(users[-1]), "google", client)
        assert refresher.last(users[-1], "google").cached_token is not None
        await cache.get(_POOL, _tenant(users[0]), "google", client)
        assert refresher.last(users[0], "google").cached_token is None


# ---------------------------------------------------------------------------
# 9. AccessTokenCache.get: call-through, caching and keys
# ---------------------------------------------------------------------------


class TestAccessTokenCacheGet:
    """get() asks get_valid_access_token with the key's cached token and caches the result."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_first_get_calls_through_with_nothing_cached(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """The first get passes no cached token or expiry and returns the minted token."""
        a = uuid.uuid4()
        cache = oauth.AccessTokenCache()

        token = await cache.get(_POOL, _tenant(a), "google", client)

        call = refresher.last(a, "google")
        assert call.cached_token is None
        assert call.cached_expires_at is None
        assert token == refresher.minted[(a, "google")][0]
        assert len(cache) == 1

    async def test_oauth_cache_second_get_passes_cached_token_and_expiry_back(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """The second get hands the stored token and expiry to the refresh and returns it."""
        a = uuid.uuid4()
        cache = oauth.AccessTokenCache()
        first = await cache.get(_POOL, _tenant(a), "google", client)

        second = await cache.get(_POOL, _tenant(a), "google", client)

        calls = refresher.calls_for(a, "google")
        assert len(calls) == 2
        assert calls[1].cached_token == first
        assert calls[1].cached_expires_at is not None
        assert calls[1].cached_expires_at > datetime.now(UTC)
        assert second == first
        assert len(refresher.minted[(a, "google")]) == 1

    async def test_oauth_cache_get_passes_pool_tenant_provider_and_client_through(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """The refresh gets the caller's pool, tenant, provider and http client."""
        a = uuid.uuid4()
        tenant = _tenant(a)
        cache = oauth.AccessTokenCache()

        await cache.get(_POOL, tenant, "microsoft", client)

        call = refresher.last(a, "microsoft")
        assert call.pool is _POOL
        assert call.tenant == tenant
        assert call.provider == "microsoft"
        assert call.http_client is client

    async def test_oauth_cache_keys_are_user_and_provider(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """A's Google token is never handed to B or to A's Microsoft refresh."""
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        token_a = await cache.get(_POOL, _tenant(a), "google", client)

        token_b = await cache.get(_POOL, _tenant(b, role="org_admin"), "google", client)
        token_a_ms = await cache.get(_POOL, _tenant(a), "microsoft", client)

        assert refresher.last(b, "google").cached_token is None
        assert refresher.last(b, "google").tenant.user_id == b
        assert refresher.last(a, "microsoft").cached_token is None
        assert token_b == refresher.minted[(b, "google")][0]
        assert token_a_ms == refresher.minted[(a, "microsoft")][0]
        assert len({token_a, token_b, token_a_ms}) == 3
        assert len(cache) == 3

    async def test_oauth_cache_users_of_different_orgs_share_no_entry(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """Two users of different orgs never share an entry."""
        a, c = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        await cache.get(_POOL, _tenant(a), "google", client)

        token_c = await cache.get(_POOL, _tenant(c, OTHER_ORG_ID), "google", client)

        assert refresher.last(c, "google").cached_token is None
        assert token_c == refresher.minted[(c, "google")][0]


# ---------------------------------------------------------------------------
# 10. AccessTokenCache: concurrency (one lock per key)
# ---------------------------------------------------------------------------


class TestAccessTokenCacheConcurrency:
    """Different users never wait on or see each other; one key refreshes one at a time."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_blocked_refresh_of_a_never_delays_b(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """A's refresh hangs; B's completes with B's token; then A gets A's token."""
        a, b = uuid.uuid4(), uuid.uuid4()
        gate = asyncio.Event()
        refresher.gates[(a, "google")] = gate
        cache = oauth.AccessTokenCache()
        task_a = asyncio.create_task(cache.get(_POOL, _tenant(a), "google", client))
        try:
            await asyncio.wait_for(refresher.entered[(a, "google")].wait(), _WAIT)

            token_b = await asyncio.wait_for(cache.get(_POOL, _tenant(b), "google", client), _WAIT)
            assert not task_a.done()

            gate.set()
            token_a = await asyncio.wait_for(task_a, _WAIT)
        finally:
            gate.set()
            await asyncio.gather(task_a, return_exceptions=True)

        assert token_b == refresher.minted[(b, "google")][0]
        assert token_a == refresher.minted[(a, "google")][0]
        assert token_a != token_b
        assert await cache.get(_POOL, _tenant(a), "google", client) == token_a
        assert await cache.get(_POOL, _tenant(b), "google", client) == token_b
        assert refresher.last(a, "google").cached_token == token_a
        assert refresher.last(b, "google").cached_token == token_b

    @pytest.mark.parametrize("seed", range(5))
    async def test_oauth_cache_twenty_users_concurrently_each_get_their_own_token(
        self, refresher: _FakeRefresher, client: AsyncMock, seed: int
    ) -> None:
        """20 users x 2 providers refresh at once (all held at a barrier, then released in a
        seed-dependent order); each key gets exactly its own token, now and when cached."""
        users = _users(20)
        tenants = {user: _tenant(user) for user in users}
        keys = _shuffled([(user, provider) for user in users for provider in _PROVIDERS], seed)
        refresher.barrier = asyncio.Barrier(len(keys))
        refresher.yields = {key: (index * 5 + seed * 3) % 7 for index, key in enumerate(keys)}
        cache = oauth.AccessTokenCache()

        first = await asyncio.wait_for(
            asyncio.gather(*(cache.get(_POOL, tenants[u], p, client) for u, p in keys)),
            _WAIT * 2,
        )

        for (user, provider), token in zip(keys, first, strict=True):
            assert refresher.minted[(user, provider)] == [token]
        refresher.barrier = None
        again = _shuffled(keys, seed + 1)
        second = await asyncio.wait_for(
            asyncio.gather(*(cache.get(_POOL, tenants[u], p, client) for u, p in again)),
            _WAIT * 2,
        )
        for (user, provider), token in zip(again, second, strict=True):
            assert token == refresher.minted[(user, provider)][0]
            assert refresher.last(user, provider).cached_token == token
        assert len(cache) == len(keys)

    async def test_oauth_cache_concurrent_gets_of_one_key_refresh_one_at_a_time(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """Ten concurrent gets of A's Google key never overlap; one token is minted and shared."""
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        jobs = [_tenant(a) if index % 2 == 0 else _tenant(b) for index in range(20)]

        tokens = await asyncio.wait_for(
            asyncio.gather(*(cache.get(_POOL, tenant, "google", client) for tenant in jobs)),
            _WAIT,
        )

        assert refresher.max_in_flight[(a, "google")] == 1
        assert refresher.max_in_flight[(b, "google")] == 1
        assert refresher.minted[(a, "google")] == [tokens[0]]
        assert refresher.minted[(b, "google")] == [tokens[1]]
        assert set(tokens[0::2]) == {tokens[0]}
        assert set(tokens[1::2]) == {tokens[1]}

    async def test_oauth_cache_gets_of_different_keys_run_concurrently(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """Refreshes for different users overlap (no global lock)."""
        users = _users(5)
        cache = oauth.AccessTokenCache()

        await asyncio.wait_for(
            asyncio.gather(*(cache.get(_POOL, _tenant(u), "google", client) for u in users)),
            _WAIT,
        )

        assert refresher.max_total_in_flight > 1


# ---------------------------------------------------------------------------
# 11. AccessTokenCache: bounded LRU
# ---------------------------------------------------------------------------


class TestAccessTokenCacheLru:
    """At most max_entries keys; the least recently used one goes first."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_fourth_key_evicts_the_least_recently_used(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """With 3 slots, a 4th user evicts the first; the other two stay cached."""
        users = _users(4)
        cache = oauth.AccessTokenCache(max_entries=3)
        for user in users:
            await cache.get(_POOL, _tenant(user), "google", client)

        assert len(cache) == 3
        for user in users[1:]:
            await cache.get(_POOL, _tenant(user), "google", client)
            assert refresher.last(user, "google").cached_token is not None
        await cache.get(_POOL, _tenant(users[0]), "google", client)
        assert refresher.last(users[0], "google").cached_token is None

    async def test_oauth_cache_get_marks_its_key_most_recently_used(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """Re-reading the oldest key protects it: the next new key evicts the second one."""
        u0, u1, u2, u3 = _users(4)
        cache = oauth.AccessTokenCache(max_entries=3)
        for user in (u0, u1, u2):
            await cache.get(_POOL, _tenant(user), "google", client)
        await cache.get(_POOL, _tenant(u0), "google", client)

        await cache.get(_POOL, _tenant(u3), "google", client)

        await cache.get(_POOL, _tenant(u0), "google", client)
        assert refresher.last(u0, "google").cached_token is not None
        await cache.get(_POOL, _tenant(u1), "google", client)
        assert refresher.last(u1, "google").cached_token is None

    async def test_oauth_cache_len_never_exceeds_the_bound(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """len() grows to the bound and stays there; providers count as separate keys."""
        cache = oauth.AccessTokenCache(max_entries=3)
        keys = [(user, provider) for user in _users(5) for provider in _PROVIDERS]

        for index, (user, provider) in enumerate(keys):
            await cache.get(_POOL, _tenant(user), provider, client)
            assert len(cache) == min(index + 1, 3)
        assert len(refresher.calls) == len(keys)


# ---------------------------------------------------------------------------
# 12. AccessTokenCache: invalidate and clear
# ---------------------------------------------------------------------------


class TestAccessTokenCacheInvalidate:
    """invalidate(user_id, provider) drops exactly one key; clear() drops all."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_invalidate_drops_only_that_key(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """A's Google entry goes; A's Microsoft and B's Google entries stay."""
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        await cache.get(_POOL, _tenant(a), "google", client)
        await cache.get(_POOL, _tenant(a), "microsoft", client)
        await cache.get(_POOL, _tenant(b), "google", client)

        await cache.invalidate(a, "google")

        assert len(cache) == 2
        await cache.get(_POOL, _tenant(a), "google", client)
        assert refresher.last(a, "google").cached_token is None
        await cache.get(_POOL, _tenant(a), "microsoft", client)
        assert refresher.last(a, "microsoft").cached_token is not None
        await cache.get(_POOL, _tenant(b), "google", client)
        assert refresher.last(b, "google").cached_token is not None

    async def test_oauth_cache_invalidate_unknown_key_changes_nothing(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """Invalidating a key that isn't cached is harmless."""
        a = uuid.uuid4()
        cache = oauth.AccessTokenCache()
        await cache.get(_POOL, _tenant(a), "google", client)

        await cache.invalidate(uuid.uuid4(), "google")
        await cache.invalidate(a, "microsoft")

        assert len(cache) == 1
        await cache.get(_POOL, _tenant(a), "google", client)
        assert refresher.last(a, "google").cached_token is not None

    async def test_oauth_cache_invalidate_during_inflight_refresh_never_restores_token(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """A disconnect while A's refresh is in flight: the refreshed token is not cached."""
        a = uuid.uuid4()
        gate = asyncio.Event()
        refresher.gates[(a, "google")] = gate
        cache = oauth.AccessTokenCache()
        task = asyncio.create_task(cache.get(_POOL, _tenant(a), "google", client))
        invalidation: asyncio.Task[None] | None = None
        try:
            await asyncio.wait_for(refresher.entered[(a, "google")].wait(), _WAIT)
            invalidation = asyncio.create_task(cache.invalidate(a, "google"))
            for _ in range(10):
                await asyncio.sleep(0)
            gate.set()
            token = await asyncio.wait_for(task, _WAIT)
            await asyncio.wait_for(invalidation, _WAIT)
        finally:
            gate.set()
            await asyncio.gather(
                task, *([invalidation] if invalidation else []), return_exceptions=True
            )

        assert token == refresher.minted[(a, "google")][0]
        assert len(cache) == 0
        del refresher.gates[(a, "google")]
        await cache.get(_POOL, _tenant(a), "google", client)
        assert refresher.last(a, "google").cached_token is None

    async def test_oauth_cache_clear_empties_every_entry(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """clear() drops every key; the next get loads afresh."""
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        await cache.get(_POOL, _tenant(a), "google", client)
        await cache.get(_POOL, _tenant(a), "microsoft", client)
        await cache.get(_POOL, _tenant(b), "google", client)

        cache.clear()

        assert len(cache) == 0
        await cache.get(_POOL, _tenant(b), "google", client)
        assert refresher.last(b, "google").cached_token is None


# ---------------------------------------------------------------------------
# 13. AccessTokenCache: errors
# ---------------------------------------------------------------------------


_ERRORS: dict[str, Callable[[], Exception]] = {
    "not_connected": lambda: OAuthError("No google account is connected."),
    "terminal_refresh": lambda: OAuthRefreshError("authorization revoked", terminal=True),
    "transient_refresh": lambda: OAuthRefreshError("token endpoint 503", terminal=False),
}


class TestAccessTokenCacheErrors:
    """Refresh errors propagate unchanged and nothing is cached."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("kind", sorted(_ERRORS))
    async def test_oauth_cache_error_propagates_unchanged_and_nothing_is_cached(
        self, refresher: _FakeRefresher, client: AsyncMock, kind: str
    ) -> None:
        """The very exception the refresh raised reaches the caller; the key stays empty."""
        a = uuid.uuid4()
        raised: list[Exception] = []

        def _make() -> Exception:
            raised.append(_ERRORS[kind]())
            return raised[-1]

        refresher.errors[(a, "google")] = _make
        cache = oauth.AccessTokenCache()

        with pytest.raises(OAuthError) as exc_info:
            await cache.get(_POOL, _tenant(a), "google", client)

        assert exc_info.value is raised[0]
        if isinstance(raised[0], OAuthRefreshError):
            assert isinstance(exc_info.value, OAuthRefreshError)
            assert exc_info.value.terminal is raised[0].terminal
        assert len(cache) == 0
        del refresher.errors[(a, "google")]
        await cache.get(_POOL, _tenant(a), "google", client)
        assert refresher.last(a, "google").cached_token is None

    async def test_oauth_cache_error_for_a_keeps_bs_entry(
        self, refresher: _FakeRefresher, client: AsyncMock
    ) -> None:
        """A failing refresh of A leaves B's cached token alone."""
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache()
        token_b = await cache.get(_POOL, _tenant(b), "google", client)
        refresher.errors[(a, "google")] = _ERRORS["terminal_refresh"]

        with pytest.raises(OAuthRefreshError):
            await cache.get(_POOL, _tenant(a), "google", client)

        assert len(cache) == 1
        assert await cache.get(_POOL, _tenant(b), "google", client) == token_b
        assert refresher.last(b, "google").cached_token == token_b


# ---------------------------------------------------------------------------
# 14. AccessTokenCache with the real refresh against FakeDb
# ---------------------------------------------------------------------------


class TestAccessTokenCacheWithRealRefresh:
    """End to end: the cache, the real get_valid_access_token, FakeDb and a mocked endpoint."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_refreshes_each_tenant_with_their_own_refresh_token(
        self, world: _World
    ) -> None:
        """A and B each get the access token of their own refresh token; then both are cached."""
        plain_a, plain_b = _plain("A"), _plain("B")
        _seed(world.db, world.a, "google", plain_a)
        _seed(world.db, world.b, "google", plain_b)
        client = _refresh_client()
        cache = oauth.AccessTokenCache()

        token_a = await cache.get(world.db.pool, world.ta, "google", client)
        token_b = await cache.get(world.db.pool, world.tb, "google", client)

        assert token_a == _access_for(plain_a)
        assert token_b == _access_for(plain_b)
        assert _posted(client, "refresh_token") == [plain_a, plain_b]
        assert await cache.get(world.db.pool, world.ta, "google", client) == token_a
        assert await cache.get(world.db.pool, world.tb, "google", client) == token_b
        assert client.post.await_count == 2

    async def test_oauth_cache_blocked_refresh_of_a_while_b_completes_with_real_refresh(
        self, world: _World
    ) -> None:
        """A's token endpoint call hangs; B's request completes with B's token; then A's."""
        plain_a, plain_b = _plain("A"), _plain("B")
        _seed(world.db, world.a, "google", plain_a)
        _seed(world.db, world.b, "google", plain_b)
        a_entered, release_a = asyncio.Event(), asyncio.Event()
        client = AsyncMock(spec=httpx.AsyncClient)

        async def _post(url: str, *args: Any, **kwargs: Any) -> httpx.Response:
            _ = url, args
            refresh_token = kwargs["data"]["refresh_token"]
            if refresh_token == plain_a:
                a_entered.set()
                await asyncio.wait_for(release_a.wait(), _WAIT)
            return httpx.Response(
                200, json={"access_token": _access_for(refresh_token), "expires_in": 3600}
            )

        client.post.side_effect = _post
        cache = oauth.AccessTokenCache()
        task_a = asyncio.create_task(cache.get(world.db.pool, world.ta, "google", client))
        try:
            await asyncio.wait_for(a_entered.wait(), _WAIT)
            token_b = await asyncio.wait_for(
                cache.get(world.db.pool, world.tb, "google", client), _WAIT
            )
            assert not task_a.done()
            release_a.set()
            token_a = await asyncio.wait_for(task_a, _WAIT)
        finally:
            release_a.set()
            await asyncio.gather(task_a, return_exceptions=True)

        assert token_b == _access_for(plain_b)
        assert token_a == _access_for(plain_a)
        assert _row(world.db, world.a, "google")["healthy"] is True
        assert _row(world.db, world.b, "google")["healthy"] is True

    @pytest.mark.parametrize("seed", range(3))
    async def test_oauth_cache_twenty_users_concurrent_real_refresh_each_get_their_own(
        self, oauth_env: None, seed: int
    ) -> None:
        """20 users of one org refresh at once through the real path; nobody gets another's."""
        _ = oauth_env
        db = FakeDb()
        users = [db.add_account(role="editor") for _ in range(20)]
        plains = {user: _plain(f"U{index}") for index, user in enumerate(users)}
        for user in users:
            _seed(db, user, "google", plains[user])
        barrier = asyncio.Barrier(len(users))
        delays = {plains[user]: (index * 5 + seed * 3) % 7 for index, user in enumerate(users)}
        client = AsyncMock(spec=httpx.AsyncClient)

        async def _post(url: str, *args: Any, **kwargs: Any) -> httpx.Response:
            _ = url, args
            refresh_token = kwargs["data"]["refresh_token"]
            await asyncio.wait_for(barrier.wait(), _WAIT)
            for _ in range(delays[refresh_token]):
                await asyncio.sleep(0)
            return httpx.Response(
                200, json={"access_token": _access_for(refresh_token), "expires_in": 3600}
            )

        client.post.side_effect = _post
        cache = oauth.AccessTokenCache()
        order = _shuffled(users, seed)

        tokens = await asyncio.wait_for(
            asyncio.gather(*(cache.get(db.pool, _tenant(u), "google", client) for u in order)),
            _WAIT * 2,
        )

        for user, token in zip(order, tokens, strict=True):
            assert token == _access_for(plains[user])
            assert _decrypt(_row(db, user, "google")["encrypted_refresh_token"]) == plains[user]
        assert sorted(_posted(client, "refresh_token")) == sorted(plains.values())


# ---------------------------------------------------------------------------
# 15. No tokens or user ids in logs
# ---------------------------------------------------------------------------


class TestNoSecretsInLogs:
    """Neither the cache nor the per-user OAuth flow logs a token, an email or a user id."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_cache_never_logs_a_token_or_a_user_id(
        self,
        refresher: _FakeRefresher,
        client: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Gets, a cache hit, an error, invalidate, eviction and clear log no secret or id."""
        caplog.set_level(logging.DEBUG)
        a, b = uuid.uuid4(), uuid.uuid4()
        cache = oauth.AccessTokenCache(max_entries=2)
        logging.getLogger("admino.oauth").debug("gh162 cache log marker")

        await cache.get(_POOL, _tenant(a), "google", client)
        await cache.get(_POOL, _tenant(a), "google", client)
        await cache.get(_POOL, _tenant(b), "microsoft", client)
        await cache.get(_POOL, _tenant(b), "google", client)
        refresher.errors[(a, "microsoft")] = _ERRORS["terminal_refresh"]
        with pytest.raises(OAuthRefreshError):
            await cache.get(_POOL, _tenant(a), "microsoft", client)
        await cache.invalidate(b, "google")
        cache.clear()

        text = _log_text(caplog)
        assert "gh162 cache log marker" in text
        tokens = [token for minted in refresher.minted.values() for token in minted]
        assert len(tokens) == 3
        for secret in tokens:
            assert secret not in text
        for user in (a, b):
            assert str(user) not in text
            assert user.hex not in text

    async def test_oauth_per_user_flow_never_logs_tokens_emails_or_user_ids(
        self, world: _World, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Save, load, status, cached refresh, terminal failure, revoke and delete log no secret."""
        caplog.set_level(logging.DEBUG)
        plain_a, plain_b = _plain("A"), _plain("B")
        email_a, email_b = "anna.a@example.test", "ben.b@example.test"
        pool = world.db.pool
        logging.getLogger("admino.oauth").debug("gh162 flow log marker")
        token_a = _token("google", plain_a, email=email_a)
        await oauth.save_token(pool, world.ta, token_a)
        _seed(world.db, world.b, "google", plain_b, email=email_b)
        await oauth.load_token(pool, world.ta, "google")
        await oauth.get_connection_status(pool, world.ta, "google")
        cache = oauth.AccessTokenCache()
        access_a = await cache.get(pool, world.ta, "google", _refresh_client())
        with pytest.raises(OAuthRefreshError):
            await oauth.get_valid_access_token(
                pool, world.tb, "google", None, None, _invalid_grant_client()
            )
        await oauth.revoke_and_delete_token(pool, world.ta, "google", _refresh_client())
        await oauth.delete_token(pool, world.tb, "google")
        await cache.invalidate(world.a, "google")

        text = _log_text(caplog)
        assert "gh162 flow log marker" in text
        secrets_and_ids = [
            plain_a,
            plain_b,
            token_a.encrypted_refresh_token,
            access_a,
            email_a,
            email_b,
            str(world.a),
            world.a.hex,
            str(world.b),
            world.b.hex,
        ]
        for value in secrets_and_ids:
            assert value not in text
