"""End-to-end spec for per-user connections and memory through the chat route (GH-162).

The FastAPI app from ``create_app()`` runs a REAL ``Agent`` (with the real
tool-call recorder of ``main._build_tool_call_recorder()``) against the
in-memory database of tests/db_fakes.py (what ``admino.database.get_pool``
returns). The real ``require_session``, ``org_permissions.load_tool_policy``,
``scoped_settings``, registry dispatch and tool handlers run; the registry
holds the real memory handlers and the real connector handlers of the six
Google/Microsoft tools. Only the LLM is a fake (``_FakeLLM``: each chat's user
message picks a script of tool calls; it records the ``tools`` payload and the
tool results it is fed), and every connector module's HTTP client points at a
mocked provider API (``_Api``), so no network call is ever made. Users are
FakeDb accounts with real session cookies.

What these tests pin down (GH-162, contract sections 5, 7, 8, 9 and 10):
- Memory per user: ``memory.store`` / ``recall`` / ``list`` see only the
  calling user's notes. Another user of the same org, or of another org,
  never reads, lists or overwrites them; a store of the same key keeps both
  users' notes. Every memory statement binds the caller's user id AND org id
  (from the server-side context), never another user's.
- An LLM-supplied ``user_id`` / ``org_id`` / ``tenant`` / ``session_id``
  argument is refused with the existing "unexpected fields" result: the
  handler isn't called, and the next plain call still runs for the caller.
- Residency (``organizations.data_residency``): on, the tools payload has no
  gmail / google_calendar / google_drive / outlook / outlook_calendar /
  onedrive function (memory stays), a promoted ``gmail.send`` included; a
  scripted call is rejected with ``"Tool '<tool>' is disabled."``, no token
  is loaded (no token getter, no oauth_tokens statement, no API request) and
  the ``tool.call`` audit row says ``deny``. The stored connection is kept.
  Off, ``gmail.search`` is advertised and dispatched with the caller's
  ``TenantContext``. Residency is read per org and per request.
- Roles: a Viewer gets 403 on POST /api/message (no LLM call, no tool, no
  token); a demoted user's oauth_tokens row and notes are kept, and promoting
  them back reactivates both (their recall works, their token getter receives
  their tenant).
- Tokens per user: concurrent chats of two users (same org or not) that both
  search Gmail each send only their own access token; the token refresh is
  keyed by the tenant and never handed another user's cached token.
- No note, key or access token in any app log record.

Contract names used here: ``admino.oauth.access_tokens`` (cleared around each
test, looked up with getattr so the file collects before it exists),
``admino.oauth.get_valid_access_token(pool, tenant, provider, cached_token,
cached_expires_at, http_client)`` and the per-module token getters
``_get_google_token(tenant)`` / ``_get_microsoft_token(tenant)``.

All database calls are faked. No network, no real PostgreSQL, no real LLM.

Security notes:
- Tenant isolation: the tool context comes from the session's principal only,
  never from LLM arguments; content queries filter by org AND user.
- One user's OAuth access token is never used for another user's request,
  under concurrency included.
- Residency fails closed: the connector tools are neither advertised nor
  dispatchable, and no token is even loaded.
- The tokens and notes here are fixed fake values, never real secrets.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient

from admino import main as main_module
from admino import oauth, server
from admino.access import Principal
from admino.agent import Agent
from admino.config import AppConfig
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    GmailSearchArgs,
    GmailSendArgs,
    GoogleCalendarListArgs,
    GoogleDriveSearchArgs,
    MemoryListArgs,
    MemoryRecallArgs,
    MemoryStoreArgs,
    OneDriveSearchArgs,
    OutlookCalendarListArgs,
    OutlookSearchArgs,
    ToolCall,
)
from admino.server import create_app
from admino.tenancy import TenantContext
from admino.tools import (
    gmail,
    google_calendar,
    google_drive,
    memory,
    onedrive,
    outlook,
    outlook_calendar,
    registry,
)
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, Call, FakeDb, plain

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable, Iterator
    from types import ModuleType

    from fastapi import FastAPI

    from admino.access import MemberRole
    from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.162"
_FORBIDDEN: Final = {"detail": "Forbidden"}
_FINAL_REPLY: Final = "All done."

_KEY: Final = "plan"
_A_SECRET: Final = "A-secret"
_B_VALUE: Final = "B-value"
_NOT_FOUND: Final = "No memory found for key: plan"
_STORED: Final = "Stored memory: plan"
_NO_MEMORIES: Final = "No memories stored."
_EXTRA_REFUSED: Final = "Argument validation failed: unexpected fields are not permitted."

# The tools an org's data residency switches off (contract: RESIDENCY_BLOCKED_TOOLS).
_RESIDENCY_TOOLS: Final = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
)
_MEMORY_FUNCTIONS: Final = frozenset({"memory.store", "memory.recall", "memory.list"})

# tool -> (module, token getter name): the getters tests patch per module (contract 7).
_TOKEN_GETTERS: Final[dict[str, tuple[ModuleType, str]]] = {
    "gmail": (gmail, "_get_google_token"),
    "google_calendar": (google_calendar, "_get_google_token"),
    "google_drive": (google_drive, "_get_google_token"),
    "outlook": (outlook, "_get_microsoft_token"),
    "outlook_calendar": (outlook_calendar, "_get_microsoft_token"),
    "onedrive": (onedrive, "_get_microsoft_token"),
}
_CONNECTOR_MODULES: Final = (
    gmail,
    google_calendar,
    google_drive,
    outlook,
    outlook_calendar,
    onedrive,
)

# The registry this module runs with: the real handlers.
_REGISTERED: Final[list[tuple[str, str, type[Any], Callable[..., Any]]]] = [
    ("memory", "store", MemoryStoreArgs, memory.memory_store),
    ("memory", "recall", MemoryRecallArgs, memory.memory_recall),
    ("memory", "list", MemoryListArgs, memory.memory_list),
    ("gmail", "search", GmailSearchArgs, gmail.gmail_search),
    ("gmail", "send", GmailSendArgs, gmail.gmail_send),
    ("google_calendar", "list", GoogleCalendarListArgs, google_calendar.google_calendar_list),
    ("google_drive", "search", GoogleDriveSearchArgs, google_drive.google_drive_search),
    ("outlook", "search", OutlookSearchArgs, outlook.outlook_search),
    ("outlook_calendar", "list", OutlookCalendarListArgs, outlook_calendar.outlook_calendar_list),
    ("onedrive", "search", OneDriveSearchArgs, onedrive.onedrive_search),
]

# One valid call per residency-blocked tool (tool, action, args).
_CONNECTOR_CALLS: Final = [
    pytest.param("gmail", "search", {"query": "from:auditor@example.ch"}, id="gmail.search"),
    pytest.param(
        "google_calendar",
        "list",
        {"time_min": "2026-10-01T00:00:00Z", "time_max": "2026-10-08T00:00:00Z"},
        id="google_calendar.list",
    ),
    pytest.param("google_drive", "search", {"query": "board minutes"}, id="google_drive.search"),
    pytest.param("outlook", "search", {"query": "board minutes"}, id="outlook.search"),
    pytest.param(
        "outlook_calendar",
        "list",
        {"time_min": "2026-10-01T00:00:00Z", "time_max": "2026-10-08T00:00:00Z"},
        id="outlook_calendar.list",
    ),
    pytest.param("onedrive", "search", {"query": "board minutes"}, id="onedrive.search"),
]

_GMAIL_HOST: Final = "gmail.googleapis.com"
_MESSAGES_PATH: Final = "/gmail/v1/users/me/messages"
_GMAIL_TOKEN: Final = "ya29.gmail-token-of-the-caller-162"
_TOKEN_A: Final = "ya29.access-token-of-user-a-162"
_TOKEN_B: Final = "ya29.access-token-of-user-b-162"
_ENCRYPTED: Final = "gAAAAA-fake-fernet-ciphertext-162"

# ---------------------------------------------------------------------------
# Fakes: the LLM, the provider APIs, the token refresh
# ---------------------------------------------------------------------------

Step = tuple[str, str, dict[str, Any]]


@dataclass(frozen=True)
class _LLMCall:
    """What one LLM call received: the chat's current user message, the function names
    of the tools payload, and the tool results after that user message."""

    user_message: str
    functions: frozenset[str]
    tool_results: tuple[str, ...]


class _FakeLLM:
    """Plays a script per user message: the n-th call of a chat turn returns the n-th
    scripted tool call (counted by the assistant turns after the user message), then a
    final reply. Concurrent chats are told apart by their user message."""

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[_LLMCall] = []

    def script(self, message: str, *steps: Step) -> str:
        """Script the tool calls the LLM makes for ``message``; return the message."""
        number = len(self._scripts)
        self._scripts[message] = [
            ToolCall(tool=tool, action=action, args=args, tool_call_id=f"call-{number}-{index}")
            for index, (tool, action, args) in enumerate(steps)
        ]
        return message

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        last_user = max(index for index, message in enumerate(messages) if message.role == "user")
        user_message = str(messages[last_user].content)
        after = messages[last_user + 1 :]
        self.calls.append(
            _LLMCall(
                user_message=user_message,
                functions=frozenset(str(entry["function"]["name"]) for entry in tools or []),
                tool_results=tuple(str(m.content) for m in after if m.role == "tool"),
            )
        )
        steps = self._scripts.get(user_message, [])
        done = sum(1 for message in after if message.role == "assistant")
        if done < len(steps):
            return LLMResponse(content="", tool_calls=[steps[done]])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""

    def calls_of(self, message: str) -> list[_LLMCall]:
        return [call for call in self.calls if call.user_message == message]

    def results_of(self, message: str) -> list[str]:
        """The tool results the LLM was fed in the last call of ``message``'s turn."""
        calls = self.calls_of(message)
        assert calls, f"the LLM never saw {message!r}"
        return list(calls[-1].tool_results)

    def functions_of(self, message: str) -> frozenset[str]:
        """The tools payload of the first call of ``message``'s turn."""
        calls = self.calls_of(message)
        assert calls, f"the LLM never saw {message!r}"
        return calls[0].functions


class _Barrier:
    """Holds every arriving caller until ``parties`` callers are waiting at once."""

    def __init__(self, parties: int) -> None:
        self.parties = parties
        self.arrived = 0
        self.event = asyncio.Event()

    async def arrive(self) -> None:
        self.arrived += 1
        if self.arrived >= self.parties:
            self.event.set()
        await asyncio.wait_for(self.event.wait(), timeout=5)


def _subject(message_id: str) -> str:
    return f"Subject of {message_id}"


class _Api:
    """The mocked provider APIs behind every connector module's HTTP client.

    A Gmail search answers one message id (``message_ids[query]``); that message's
    metadata has the subject ``_subject(id)``. Everything else is a 404. Every request
    is recorded; ``search_barrier`` holds the searches until enough are in flight.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.message_ids: dict[str, str] = {}
        self.search_barrier: _Barrier | None = None

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == _GMAIL_HOST and request.url.path == _MESSAGES_PATH:
            if self.search_barrier is not None:
                await self.search_barrier.arrive()
            message_id = self.message_ids.get(request.url.params.get("q", ""), "msg-unknown")
            return httpx.Response(
                200, json={"messages": [{"id": message_id}], "resultSizeEstimate": 1}
            )
        if request.url.host == _GMAIL_HOST and request.url.path.startswith(_MESSAGES_PATH + "/"):
            message_id = request.url.path.rsplit("/", 1)[1]
            headers = [
                {"name": "Subject", "value": _subject(message_id)},
                {"name": "From", "value": "Sender <sender@example.ch>"},
                {"name": "Date", "value": "Thu, 01 Oct 2026 09:00:00 +0200"},
            ]
            return httpx.Response(200, json={"id": message_id, "payload": {"headers": headers}})
        return httpx.Response(404, json={"error": {"code": 404, "message": "Not Found"}})

    def gmail_requests(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.url.host == _GMAIL_HOST]

    def message_id_of(self, request: httpx.Request) -> str:
        """The Gmail message a request is about (a search: the id it answers)."""
        if request.url.path == _MESSAGES_PATH:
            return self.message_ids.get(request.url.params.get("q", ""), "msg-unknown")
        return request.url.path.rsplit("/", 1)[1]


@dataclass(frozen=True)
class _RefreshCall:
    user_id: uuid.UUID
    provider: str
    cached_token: str | None


class _PerUserRefresh:
    """Stands in for ``admino.oauth.get_valid_access_token``: each user's own access token,
    keyed by the tenant argument. A cached token that is still valid is returned as is,
    like the real function. The first calls wait until ``barrier.parties`` are in flight."""

    def __init__(self, tokens: dict[uuid.UUID, str], barrier: _Barrier | None = None) -> None:
        self.tokens = tokens
        self.barrier = barrier
        self.calls: list[_RefreshCall] = []

    async def __call__(
        self,
        pool: Any,
        tenant: TenantContext,
        provider: str,
        cached_token: str | None,
        cached_expires_at: datetime | None,
        http_client: Any,
    ) -> tuple[str, datetime]:
        user_id = plain(tenant.user_id)
        self.calls.append(_RefreshCall(user_id, provider, cached_token))
        if self.barrier is not None:
            await self.barrier.arrive()
        now = datetime.now(UTC)
        if (
            cached_token is not None
            and cached_expires_at is not None
            and cached_expires_at > now + timedelta(seconds=60)
        ):
            return cached_token, cached_expires_at
        return self.tokens[user_id], now + timedelta(hours=1)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Member:
    """A stored member account with a live session."""

    id: uuid.UUID
    org_id: uuid.UUID
    token: str

    def tenant(self, role: MemberRole = "editor") -> TenantContext:
        """The TenantContext the server derives for this member with ``role``."""
        principal = Principal(user_id=self.id, kind="member", org_id=self.org_id, role=role)
        return TenantContext.from_principal(principal)


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database every get_pool() returns: two active orgs WITHOUT data residency,
    each with the default permission matrix (memory.* and gmail.search allowed)."""
    fake = FakeDb()
    for org_id in (ORG_ID, OTHER_ORG_ID):
        fake.add_org(org_id, data_residency=False)
        fake.add_permissions(org_id)
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    # The tool modules may bind get_pool at import: point those names at the fake too.
    for module in (memory, *_CONNECTOR_MODULES):
        monkeypatch.setattr(module, "get_pool", lambda: fake.pool, raising=False)
    return fake


@pytest.fixture(autouse=True)
def _own_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unfrozen registry holding exactly ``_REGISTERED``; the previous one is restored
    after (the registry functions look ``_REGISTRY`` / ``_FROZEN`` up at call time)."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    for tool, action, schema, handler in _REGISTERED:
        registry.register_tool(tool, action, f"{tool}.{action} (GH-162 spec)", schema)(handler)


@pytest.fixture(autouse=True)
def api(monkeypatch: pytest.MonkeyPatch) -> _Api:
    """No network: every connector module's HTTP client is a mocked provider API."""
    mocked = _Api()
    for module in _CONNECTOR_MODULES:
        client = httpx.AsyncClient(transport=httpx.MockTransport(mocked.handle))
        monkeypatch.setattr(module, "_http_client", client, raising=module is not gmail)
    return mocked


@pytest.fixture(autouse=True)
def _access_token_cache() -> Iterator[None]:
    """The process-wide per-user access-token cache starts and ends empty (contract 6)."""

    def clear() -> None:
        cache = getattr(oauth, "access_tokens", None)
        if cache is not None:
            cache.clear()

    clear()
    yield
    clear()


@pytest.fixture(autouse=True)
def _roomy_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("/api/message", "/api/confirm"):
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


@pytest.fixture()
def getters(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    """Each connector module's token getter, patched with a recorder (tool -> mock)."""
    mocks: dict[str, AsyncMock] = {}
    for tool, (module, name) in _TOKEN_GETTERS.items():
        token = _GMAIL_TOKEN if tool == "gmail" else f"ya29.{tool}-token-162"
        mocks[tool] = AsyncMock(name=f"{tool}.{name}", return_value=token)
        monkeypatch.setattr(module, name, mocks[tool])
    return mocks


@pytest.fixture()
def llm() -> _FakeLLM:
    return _FakeLLM()


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )


@pytest.fixture()
def app(llm: _FakeLLM) -> FastAPI:
    """create_app with a real Agent around the fake LLM (no lifespan runs)."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
        system_prompt="You are admino.",
    )
    return create_app(agent=agent, config=_config())


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, client=(_IP, 50000), follow_redirects=False)


def _member(db: FakeDb, role: str = "editor", org_id: uuid.UUID = ORG_ID) -> _Member:
    user_id = db.add_account(role=role, org_id=org_id)
    return _Member(id=user_id, org_id=org_id, token=db.open_session(user_id))


def _cookie(member: _Member) -> dict[str, str]:
    return {"Cookie": f"{_COOKIE}={member.token}"}


def _chat(
    client: TestClient, member: _Member, message: str, chat_id: str = "chat-162"
) -> httpx.Response:
    return client.post(
        "/api/message",
        headers=_cookie(member),
        json={"message": message, "session_id": chat_id},
    )


def _ok(*responses: httpx.Response) -> None:
    for response in responses:
        assert response.status_code == 200, response.text


def _recall(key: str = _KEY) -> Step:
    return ("memory", "recall", {"key": key})


def _store(value: str, key: str = _KEY) -> Step:
    return ("memory", "store", {"key": key, "value": value})


def _search(query: str = "from:auditor@example.ch") -> Step:
    return ("gmail", "search", {"query": query})


def _tenants_of(getter: AsyncMock) -> list[Any]:
    """The tenant each await of a token getter received (None: no tenant given)."""
    tenants: list[Any] = []
    for awaited in getter.await_args_list:
        if "tenant" in awaited.kwargs:
            tenants.append(awaited.kwargs["tenant"])
        else:
            tenants.append(awaited.args[0] if awaited.args else None)
    return tenants


def _assert_only_tenant(getter: AsyncMock, expected: TenantContext) -> None:
    tenants = _tenants_of(getter)
    assert tenants, "the token getter was never awaited"
    assert tenants == [expected] * len(tenants), tenants


def _tool_audit(db: FakeDb) -> list[dict[str, Any]]:
    """The metadata of every tool.call audit row, in order."""
    return [row["metadata"] for row in db.audit_rows("tool.call")]


def _binds(call: Call, value: uuid.UUID) -> bool:
    return any(str(arg) == str(value) for arg in call.args)


_MEMORY_SQL: Final = r"(?:\bfrom memory\b|\binto memory\b|^update memory\b)"
_OAUTH_TOKENS_SQL: Final = r"\boauth_tokens\b"


# ---------------------------------------------------------------------------
# 1. Memory per user
# ---------------------------------------------------------------------------


class TestMemoryIsolation:
    """memory.* only sees the calling user's notes (contract 7)."""

    def test_per_user_connections_memory_stored_note_is_recalled_by_its_writer_only(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM
    ) -> None:
        """The issue's test: A stores "plan"; B's recall finds nothing; A's finds it."""
        a, b = _member(db), _member(db)
        client = _client(app)
        stored = llm.script("A: remember the plan", _store(_A_SECRET))
        recalled_b = llm.script("B: what is the plan?", _recall())
        recalled_a = llm.script("A: what is the plan?", _recall())

        first = _chat(client, a, stored)
        second = _chat(client, b, recalled_b)
        third = _chat(client, a, recalled_a)

        _ok(first, second, third)
        assert llm.results_of(stored) == [_STORED]
        assert db.memories_of(a.id) == {_KEY: _A_SECRET}
        assert db.memories_of(b.id) == {}
        assert llm.results_of(recalled_b) == [_NOT_FOUND]
        assert _A_SECRET not in second.text
        assert llm.results_of(recalled_a) == [_A_SECRET]

    @pytest.mark.parametrize("reader_org", [ORG_ID, OTHER_ORG_ID], ids=["same-org", "other-org"])
    def test_per_user_connections_recall_never_returns_another_users_note(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, reader_org: uuid.UUID
    ) -> None:
        a = _member(db)
        db.add_memory(a.id, _KEY, _A_SECRET)
        reader = _member(db, org_id=reader_org)
        message = llm.script("What is the plan?", _recall())

        response = _chat(_client(app), reader, message)

        _ok(response)
        assert llm.results_of(message) == [_NOT_FOUND]
        assert _A_SECRET not in response.text
        assert db.memories_of(a.id) == {_KEY: _A_SECRET}

    @pytest.mark.parametrize("writer_org", [ORG_ID, OTHER_ORG_ID], ids=["same-org", "other-org"])
    def test_per_user_connections_same_key_store_keeps_the_other_users_note(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, writer_org: uuid.UUID
    ) -> None:
        """B stores under A's key: both notes exist, each user recalls their own."""
        a = _member(db)
        db.add_memory(a.id, _KEY, _A_SECRET)
        b = _member(db, org_id=writer_org)
        client = _client(app)
        stored_b = llm.script("B: remember the plan", _store(_B_VALUE))
        recalled_b = llm.script("B: what is the plan?", _recall())
        recalled_a = llm.script("A: what is the plan?", _recall())

        first = _chat(client, b, stored_b)
        second = _chat(client, b, recalled_b)
        third = _chat(client, a, recalled_a)

        _ok(first, second, third)
        assert llm.results_of(stored_b) == [_STORED]
        assert db.memories_of(a.id) == {_KEY: _A_SECRET}
        assert db.memories_of(b.id) == {_KEY: _B_VALUE}
        assert plain(db.memory[(b.id, _KEY)]["org_id"]) == writer_org
        assert llm.results_of(recalled_b) == [_B_VALUE]
        assert llm.results_of(recalled_a) == [_A_SECRET]
        assert _A_SECRET not in second.text

    def test_per_user_connections_list_shows_only_the_callers_keys(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM
    ) -> None:
        a, b, newcomer = _member(db), _member(db), _member(db)
        c = _member(db, org_id=OTHER_ORG_ID)
        db.add_memory(a.id, _KEY, _A_SECRET)
        db.add_memory(a.id, "alpha-note", "a second note")
        db.add_memory(b.id, "beta-note", "b's note")
        db.add_memory(c.id, "gamma-note", "c's note")
        client = _client(app)
        listing: Step = ("memory", "list", {})
        messages = {
            name: llm.script(f"{name}: list my notes", listing)
            for name in ("a", "b", "c", "newcomer")
        }

        responses = [
            _chat(client, member, messages[name])
            for name, member in (("a", a), ("b", b), ("c", c), ("newcomer", newcomer))
        ]

        _ok(*responses)
        assert llm.results_of(messages["a"]) == ["alpha-note\nplan"]
        assert llm.results_of(messages["b"]) == ["beta-note"]
        assert llm.results_of(messages["c"]) == ["gamma-note"]
        assert llm.results_of(messages["newcomer"]) == [_NO_MEMORIES]

    def test_per_user_connections_memory_statements_bind_the_callers_user_and_org(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM
    ) -> None:
        """Every memory statement binds the caller's user id and org id (from the session),
        never another user's or org's."""
        a = _member(db)
        db.add_memory(a.id, _KEY, _A_SECRET)
        b = _member(db, org_id=OTHER_ORG_ID)
        message = llm.script(
            "B: store, recall and list",
            _store(_B_VALUE),
            _recall(),
            ("memory", "list", {}),
        )
        since = len(db.calls)

        response = _chat(_client(app), b, message)

        _ok(response)
        assert llm.results_of(message) == [_STORED, _B_VALUE, _KEY]
        statements = [call for call in db.calls[since:] if _matches(call, _MEMORY_SQL)]
        assert statements, "no memory statement ran"
        for call in statements:
            assert _binds(call, b.id) and _binds(call, OTHER_ORG_ID), call.sql
            assert not _binds(call, a.id) and not _binds(call, ORG_ID), call.sql


def _matches(call: Call, pattern: str) -> bool:
    return re.search(pattern, call.normalized) is not None


# ---------------------------------------------------------------------------
# 2. An LLM-supplied identity is ignored
# ---------------------------------------------------------------------------


def _smuggled(key: str, victim: _Member) -> Any:
    """The value an injected LLM puts under ``key`` to reach the victim's data."""
    values: dict[str, Any] = {
        "user_id": str(victim.id),
        "org_id": str(victim.org_id),
        "tenant": {"user_id": str(victim.id), "org_id": str(victim.org_id), "role": "org_admin"},
        "session_id": "chat-of-the-victim",
    }
    return values[key]


_CONTEXT_KEYS: Final = ["user_id", "org_id", "tenant", "session_id"]


class TestLlmSuppliedIdentityIsIgnored:
    """The tool context comes from the session, never from LLM arguments (contract 8)."""

    @pytest.mark.parametrize("key", _CONTEXT_KEYS)
    def test_per_user_connections_llm_supplied_identity_on_recall_is_refused(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, key: str
    ) -> None:
        """The issue's test: B's LLM asks for A's note with A's id: refused; the plain
        recall that follows still reads B's own (empty) notes."""
        a = _member(db)
        db.add_memory(a.id, _KEY, _A_SECRET)
        b = _member(db)
        message = llm.script(
            "B: what is the plan?",
            ("memory", "recall", {"key": _KEY, key: _smuggled(key, a)}),
            _recall(),
        )

        response = _chat(_client(app), b, message)

        _ok(response)
        results = llm.results_of(message)
        assert results == [_EXTRA_REFUSED, _NOT_FOUND]
        assert all(_A_SECRET not in result for result in results)
        assert _A_SECRET not in response.text

    @pytest.mark.parametrize("key", _CONTEXT_KEYS)
    def test_per_user_connections_llm_supplied_identity_on_store_is_refused(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, key: str
    ) -> None:
        """B's LLM tries to overwrite A's note: refused; B's plain store lands in B's notes
        and A's note is untouched."""
        a = _member(db)
        db.add_memory(a.id, _KEY, _A_SECRET)
        b = _member(db)
        message = llm.script(
            "B: overwrite the plan",
            ("memory", "store", {"key": _KEY, "value": "overwritten", key: _smuggled(key, a)}),
            _store(_B_VALUE),
        )

        response = _chat(_client(app), b, message)

        _ok(response)
        assert llm.results_of(message) == [_EXTRA_REFUSED, _STORED]
        assert db.memories_of(a.id) == {_KEY: _A_SECRET}
        assert db.memories_of(b.id) == {_KEY: _B_VALUE}

    def test_per_user_connections_llm_supplied_user_id_on_gmail_never_loads_a_token(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, getters: dict[str, AsyncMock]
    ) -> None:
        """A gmail.search with A's user_id is refused before any token is loaded; B's plain
        search then loads B's token only."""
        a, b = _member(db), _member(db)
        query = "from:auditor@example.ch"
        message = llm.script(
            "B: search my mail",
            ("gmail", "search", {"query": query, "user_id": str(a.id)}),
            _search(query),
        )

        response = _chat(_client(app), b, message)

        _ok(response)
        assert llm.results_of(message)[0] == _EXTRA_REFUSED
        _assert_only_tenant(getters["gmail"], b.tenant())
        assert a.tenant() not in _tenants_of(getters["gmail"])


# ---------------------------------------------------------------------------
# 3. Data residency
# ---------------------------------------------------------------------------


class TestResidency:
    """Residency on: the connector tools are neither advertised nor dispatchable and no
    token is loaded; off: they run with the caller's context (contracts 5 and 7)."""

    def test_per_user_connections_residency_drops_the_connector_tools_from_the_payload(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM
    ) -> None:
        """The issue's test: a residency org's run advertises memory only; a non-residency
        org's run in the same app still advertises the connector tools."""
        db.add_org(ORG_ID, data_residency=True)
        resident = _member(db, org_id=ORG_ID)
        other = _member(db, org_id=OTHER_ORG_ID)
        client = _client(app)
        hello_resident = llm.script("hello from a residency org")
        hello_other = llm.script("hello from another org")

        _ok(_chat(client, resident, hello_resident), _chat(client, other, hello_other))

        resident_functions = llm.functions_of(hello_resident)
        assert {name.split(".")[0] for name in resident_functions} & set(_RESIDENCY_TOOLS) == set()
        assert resident_functions >= _MEMORY_FUNCTIONS
        assert "gmail.search" in llm.functions_of(hello_other)

    @pytest.mark.parametrize(("tool", "action", "args"), _CONNECTOR_CALLS)
    def test_per_user_connections_residency_rejects_a_connector_call_without_a_token(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        getters: dict[str, AsyncMock],
        api: _Api,
        tool: str,
        action: str,
        args: dict[str, Any],
    ) -> None:
        """The issue's test: dispatch is rejected through the disabled path, no handler
        runs, no token is loaded, and the tool.call audit row is a deny."""
        db.add_org(ORG_ID, data_residency=True)
        user = _member(db)
        message = llm.script(f"use {tool}.{action}", (tool, action, args))

        response = _chat(_client(app), user, message)

        _ok(response)
        assert llm.results_of(message) == [f"Tool '{tool}' is disabled."]
        for getter in getters.values():
            getter.assert_not_awaited()
        assert api.requests == []
        assert [(row["tool"], row["decision"], row["success"]) for row in _tool_audit(db)] == [
            (tool, "deny", False)
        ]

    def test_per_user_connections_residency_keeps_the_connection_and_never_loads_it(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Existing connections are kept but inactive: the stored rows stay, no oauth_tokens
        statement runs and the refresh is never called; memory still works."""
        db.add_org(ORG_ID, data_residency=True)
        user = _member(db)
        db.add_oauth_token(user.id, "google", encrypted_refresh_token=_ENCRYPTED)
        db.add_oauth_token(user.id, "microsoft", encrypted_refresh_token=_ENCRYPTED)
        db.add_memory(user.id, _KEY, "my own plan")
        refresh = AsyncMock(name="get_valid_access_token")
        monkeypatch.setattr("admino.oauth.get_valid_access_token", refresh)
        message = llm.script(
            "search my mail, then recall the plan",
            _search(),
            ("outlook", "search", {"query": "board minutes"}),
            _recall(),
        )
        since = len(db.calls)

        response = _chat(_client(app), user, message)

        _ok(response)
        assert llm.results_of(message) == [
            "Tool 'gmail' is disabled.",
            "Tool 'outlook' is disabled.",
            "my own plan",
        ]
        refresh.assert_not_awaited()
        assert [call.sql for call in db.calls[since:] if _matches(call, _OAUTH_TOKENS_SQL)] == []
        assert db.oauth_token(user.id, "google") is not None
        assert db.oauth_token(user.id, "microsoft") is not None

    def test_per_user_connections_promoted_gmail_send_is_not_advertised_under_residency(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, getters: dict[str, AsyncMock]
    ) -> None:
        """A completed gmail.send promotion doesn't reopen gmail in a residency org: not in
        the payload, and a call is the disabled deny (no confirmation asked). The other
        org's same promotion is still advertised."""
        for org_id in (ORG_ID, OTHER_ORG_ID):
            db.add_permissions(org_id, {"gmail": {"send": "confirm"}})
        db.add_org(ORG_ID, data_residency=True)
        resident = _member(db, org_id=ORG_ID)
        other = _member(db, org_id=OTHER_ORG_ID)
        client = _client(app)
        send: Step = (
            "gmail",
            "send",
            {"to": ["auditor@example.ch"], "subject": "Report", "body": "Attached."},
        )
        sent = llm.script("send the report to the auditor", send)
        hello = llm.script("hello from another org")

        response = _chat(client, resident, sent)
        _ok(response, _chat(client, other, hello))

        assert "gmail.send" not in llm.functions_of(sent)
        assert response.json()["status"] == "final"
        assert llm.results_of(sent) == ["Tool 'gmail' is disabled."]
        getters["gmail"].assert_not_awaited()
        assert "gmail.send" in llm.functions_of(hello)

    def test_per_user_connections_without_residency_gmail_runs_with_the_callers_tenant(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        getters: dict[str, AsyncMock],
        api: _Api,
    ) -> None:
        """Residency off: gmail.search is advertised and dispatched; its token getter gets
        the caller's TenantContext and the Gmail API sees that token."""
        user = _member(db)
        query = "from:auditor@example.ch"
        api.message_ids[query] = "msg-own"
        message = llm.script("search my mail", _search(query))

        response = _chat(_client(app), user, message)

        _ok(response)
        assert "gmail.search" in llm.functions_of(message)
        _assert_only_tenant(getters["gmail"], user.tenant())
        assert [row["decision"] for row in _tool_audit(db)] == ["allow"]
        assert _subject("msg-own") in llm.results_of(message)[0]
        requests = api.gmail_requests()
        assert requests, "the Gmail API was never called"
        assert {request.headers["Authorization"] for request in requests} == {
            f"Bearer {_GMAIL_TOKEN}"
        }

    def test_per_user_connections_residency_is_read_on_every_request(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, getters: dict[str, AsyncMock]
    ) -> None:
        """Residency switched on between two runs of one user: the first run searches, the
        second neither advertises nor dispatches gmail."""
        user = _member(db)
        client = _client(app)
        before = llm.script("search my mail (before)", _search())
        after = llm.script("search my mail (after)", _search())

        first = _chat(client, user, before)
        awaited_before = getters["gmail"].await_count
        db.add_org(ORG_ID, data_residency=True)
        second = _chat(client, user, after)

        _ok(first, second)
        assert "gmail.search" in llm.functions_of(before)
        _assert_only_tenant(getters["gmail"], user.tenant())
        assert "gmail.search" not in llm.functions_of(after)
        assert llm.results_of(after) == ["Tool 'gmail' is disabled."]
        assert getters["gmail"].await_count == awaited_before


# ---------------------------------------------------------------------------
# 4. Roles: Viewers have no tools; demotion keeps rows inactive
# ---------------------------------------------------------------------------


class TestRolesAndDemotion:
    """A Viewer can't chat, so no tool runs; demotion keeps connections and notes, and
    promotion reactivates both (contract 10)."""

    @pytest.mark.parametrize("restored_role", ["editor", "org_admin"])
    def test_per_user_connections_demoted_users_rows_are_kept_and_come_back(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        getters: dict[str, AsyncMock],
        api: _Api,
        restored_role: MemberRole,
    ) -> None:
        user = _member(db, "editor")
        db.add_oauth_token(user.id, "google", encrypted_refresh_token=_ENCRYPTED)
        db.add_memory(user.id, _KEY, "my own plan")
        client = _client(app)
        message = llm.script("recall the plan, then search my mail", _recall(), _search())

        db.users[user.id]["role"] = "viewer"
        refused = _chat(client, user, message, chat_id="as-viewer")

        assert (refused.status_code, refused.json()) == (403, _FORBIDDEN)
        assert llm.calls == []
        assert db.audit_rows("tool.call") == []
        for getter in getters.values():
            getter.assert_not_awaited()
        assert api.requests == []
        assert db.oauth_token(user.id, "google") is not None
        assert db.memories_of(user.id) == {_KEY: "my own plan"}
        assert db.matching(r"^delete from (?:oauth_tokens|memory)\b") == []

        db.users[user.id]["role"] = restored_role
        restored = _chat(client, user, message, chat_id="restored")

        _ok(restored)
        assert llm.results_of(message)[0] == "my own plan"
        _assert_only_tenant(getters["gmail"], user.tenant(restored_role))
        assert [row["decision"] for row in _tool_audit(db)] == ["allow", "allow"]


# ---------------------------------------------------------------------------
# 5. One user's token is never used for another user
# ---------------------------------------------------------------------------


_ORDERS: Final = [pytest.param(False, id="a-first"), pytest.param(True, id="b-first")]
_PEER_ORGS: Final = [
    pytest.param(ORG_ID, id="same-org"),
    pytest.param(OTHER_ORG_ID, id="other-org"),
]


def _asgi_client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(_IP, 50000))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _post(
    client: httpx.AsyncClient, member: _Member, message: str, chat_id: str
) -> httpx.Response:
    return await client.post(
        "/api/message",
        headers=_cookie(member),
        json={"message": message, "session_id": chat_id},
    )


def _authorizations(api: _Api, owners: dict[str, uuid.UUID]) -> dict[uuid.UUID, set[str]]:
    """user -> the Authorization headers of the Gmail requests about that user's mail."""
    seen: dict[uuid.UUID, set[str]] = {}
    for request in api.gmail_requests():
        owner = owners[api.message_id_of(request)]
        seen.setdefault(owner, set()).add(request.headers.get("Authorization", ""))
    return seen


class TestTokensPerUser:
    """The issue's test: user A's token is never used for user B, including under
    concurrent requests (contracts 6 and 7)."""

    @pytest.mark.parametrize("b_first", _ORDERS)
    @pytest.mark.parametrize("peer_org", _PEER_ORGS)
    async def test_per_user_connections_concurrent_chats_never_share_a_token(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        peer_org: uuid.UUID,
        b_first: bool,
    ) -> None:
        a = _member(db, org_id=ORG_ID)
        b = _member(db, org_id=peer_org)
        refresh = _PerUserRefresh({a.id: _TOKEN_A, b.id: _TOKEN_B}, barrier=_Barrier(2))
        monkeypatch.setattr("admino.oauth.get_valid_access_token", refresh)
        api.search_barrier = _Barrier(2)
        api.message_ids.update({"from:alpha@example.ch": "msg-a", "from:bravo@example.ch": "msg-b"})
        message_a = llm.script("A: search my mail", _search("from:alpha@example.ch"))
        message_b = llm.script("B: search my mail", _search("from:bravo@example.ch"))
        sends = [(a, message_a), (b, message_b)]
        if b_first:
            sends.reverse()

        async with _asgi_client(app) as client:
            responses = await asyncio.wait_for(
                asyncio.gather(
                    *(_post(client, member, message, "together") for member, message in sends)
                ),
                timeout=20,
            )

        _ok(*responses)
        assert refresh.barrier is not None and refresh.barrier.arrived >= 2
        assert api.search_barrier.arrived == 2
        assert _authorizations(api, {"msg-a": a.id, "msg-b": b.id}) == {
            a.id: {f"Bearer {_TOKEN_A}"},
            b.id: {f"Bearer {_TOKEN_B}"},
        }
        assert {call.user_id for call in refresh.calls} == {a.id, b.id}
        assert {call.provider for call in refresh.calls} == {"google"}
        for call in refresh.calls:
            own = _TOKEN_A if call.user_id == a.id else _TOKEN_B
            assert call.cached_token in (None, own), call
        result_a, result_b = llm.results_of(message_a)[0], llm.results_of(message_b)[0]
        assert _subject("msg-a") in result_a and "msg-b" not in result_a
        assert _subject("msg-b") in result_b and "msg-a" not in result_b

    async def test_per_user_connections_warm_cache_never_serves_another_users_token(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A searches (A's token cached), then B, then A again: B's search carries B's own
        token, and B's refresh is never handed A's cached token."""
        a, b = _member(db), _member(db)
        refresh = _PerUserRefresh({a.id: _TOKEN_A, b.id: _TOKEN_B})
        monkeypatch.setattr("admino.oauth.get_valid_access_token", refresh)
        api.message_ids.update({"from:alpha@example.ch": "msg-a", "from:bravo@example.ch": "msg-b"})
        first_a = llm.script("A: search my mail", _search("from:alpha@example.ch"))
        then_b = llm.script("B: search my mail", _search("from:bravo@example.ch"))
        again_a = llm.script("A: search again", _search("from:alpha@example.ch"))

        async with _asgi_client(app) as client:
            responses = [
                await _post(client, a, first_a, "first"),
                await _post(client, b, then_b, "first"),
                await _post(client, a, again_a, "second"),
            ]

        _ok(*responses)
        assert _authorizations(api, {"msg-a": a.id, "msg-b": b.id}) == {
            a.id: {f"Bearer {_TOKEN_A}"},
            b.id: {f"Bearer {_TOKEN_B}"},
        }
        b_calls = [call for call in refresh.calls if call.user_id == b.id]
        assert b_calls, "B's token was never loaded"
        assert all(call.cached_token in (None, _TOKEN_B) for call in b_calls), b_calls


# ---------------------------------------------------------------------------
# 6. No content in logs
# ---------------------------------------------------------------------------


_NOTE_KEY: Final = "zephyr-merger-162"
_NOTE_VALUE: Final = "Zephyr-Kestrel merger closes on Friday 162"


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


class TestNoContentInLogs:
    """No memory key or value and no access token in an app log record (#139 section 5)."""

    async def test_per_user_connections_chat_with_notes_and_mail_logs_no_content(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        a, b = _member(db), _member(db)
        refresh = _PerUserRefresh({a.id: _TOKEN_A, b.id: _TOKEN_B})
        monkeypatch.setattr("admino.oauth.get_valid_access_token", refresh)
        stored = llm.script("A: remember this", _store(_NOTE_VALUE, key=_NOTE_KEY))
        searched = llm.script(
            "A: recall it and search my mail", _recall(_NOTE_KEY), _search("from:alpha@x.ch")
        )
        probed = llm.script("B: recall A's note", _recall(_NOTE_KEY), _search("from:bravo@x.ch"))

        async with _asgi_client(app) as client:
            responses = [
                await _post(client, a, stored, "notes"),
                await _post(client, a, searched, "notes"),
                await _post(client, b, probed, "probe"),
            ]

        _ok(*responses)
        assert llm.results_of(stored) == [f"Stored memory: {_NOTE_KEY}"]
        assert llm.results_of(searched)[0] == _NOTE_VALUE
        assert llm.results_of(probed)[0] == f"No memory found for key: {_NOTE_KEY}"
        text = _app_log_text(caplog)
        for marker in (_NOTE_KEY, _NOTE_VALUE, _TOKEN_A, _TOKEN_B, "Zephyr-Kestrel"):
            assert marker not in text, marker
