"""Tests for GH-179's store side: ``chats.set_auto_title`` and ``chat_titles.title_chat``.

The real ``admino.chats`` repository and the new ``admino.chat_titles`` module
run against the in-memory ``chats`` table of tests/db_fakes.py (migration
0024). The fake applies only the predicates a statement states, so a
compare-and-set without its ``title_source = 'auto'`` / ``title = ''`` guard,
or a statement without its owner, org or ``deleted_at IS NULL`` filter,
changes rows it must not.

What these tests pin down (contract §2 and the ``title_chat`` part of §3):
- ``set_auto_title(executor, tenant, chat_id, title) -> bool`` (S14): True
  and the title stored for the caller's live, untitled, automatic chat;
  ``title_source`` stays ``auto`` and ``last_activity_at`` is untouched.
  False, with every table unchanged and no ``ChatNotFoundError``, for a
  user-titled chat (an empty user title included), a chat already titled
  automatically, a trashed chat, a colleague's chat, the caller's user id under
  another org's tenant, another org's chat and an unknown id. One ``fetchval``
  UPDATE of ``chats`` binding the chat id, the caller's org and owner, stating
  ``deleted_at IS NULL``, ``title_source = 'auto'`` and ``title = ''``; the
  title travels as a bind parameter; no audit row, no log line.
- ``title_chat(pool, tenant, chat_id, *, get_client, user_message,
  assistant_message, run_failed, data_residency, max_retries) -> None``:
  - Model path: the client from ``get_client()`` (resolved once) gets ONE
    request (``build_title_messages`` of the two messages, no tools,
    ``max_tokens=TITLE_MAX_TOKENS``, no chat, org or user id), through
    ``llm_policy.chat`` (residency guard, retries up to ``max_retries``); the
    sanitized reply is stored as an ``auto`` title.
  - Fallback (the first message cut at a word boundary with U+2026): the
    client raises an ``LLMError`` or anything else, doesn't take
    ``max_tokens``, replies nothing usable, ``get_client`` raises, or a
    residency org's provider isn't Swiss (then no request at all). A failed
    run stores the fallback without resolving a client.
  - Nothing to title (a whitespace-only first message and no model title):
    nothing is written.
  - A user rename always wins: before the task, or while the title is being
    generated (model or fallback), the user's title stays; a chat trashed
    meanwhile gets nothing. Every store is one compare-and-set statement.
  - Another member's or another org's tenant changes nothing.
  - Never raises an ``Exception`` (a database error included); ``MemoryError``
    and ``RecursionError`` propagate.
  - Logs: one line per outcome carrying the chat id; never the title, the
    messages, the model's reply, an exception's text, the org or user id.

No real PostgreSQL, no network, no sleeps: every statement goes to
``FakeDb`` (or a stub executor that raises), the LLM clients are fakes and
``llm_policy._sleep`` is a recorder.

Security notes:
- Owner-private chats: the compare-and-set binds the caller's org and owner,
  so a background task can't title a colleague's or another org's chat.
- A user's rename is never overwritten by a late automatic title.
- No content reaches a log line; no identifier reaches the model provider.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import llm_policy
from admino.access import Principal
from admino.llm import LLMError, LLMResponse
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, ORG_ID_PARAM_RE, OTHER_ORG_ID, FakeDb

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import ModuleType

    from admino.models import LLMMessage
    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ELLIPSIS: Final = chr(0x2026)
_PAST: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
_UNKNOWN_CHAT: Final = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")

# The first exchange: a 110-character question (its fallback is cut after "and") and a reply.
_USER: Final = (
    "Please help me prepare the quarterly VAT filing for our Zurich office "
    "and collect every receipt from September"
)
_FALLBACK: Final = (
    "Please help me prepare the quarterly VAT filing for our Zurich office and" + _ELLIPSIS
)
_ASSISTANT: Final = "Sure. Start with the September receipts, then reconcile the input tax."
# The model's reply: quoted, a final period and a second line, all dropped by sanitize_title.
_REPLY: Final = '"Quarterly VAT filing plan."\nI hope this title helps.'
_MODEL_TITLE: Final = "Quarterly VAT filing plan"
_RENAME: Final = "My own title"
_BLANK: Final = "  \n\t  "

_CHAT_TABLE_RE: Final = re.compile(r"\b(?:chats|chat_messages)\b")
_ID_PARAM_RE: Final = r"(?<![\w])id = \$(\d+)"
_OWNER_PARAM_RE: Final = r"(?<![\w])(?:\w+\.)?owner_user_id = \$(\d+)"

_REFUSED_CASES: Final = (
    "user-titled",
    "user-titled-empty",
    "auto-titled",
    "trashed",
    "other-owner",
    "other-org-tenant",
    "other-org-chat",
    "unknown",
)
_FALLBACK_CASES: Final = (
    "llm-error",
    "runtime-error",
    "empty-reply",
    "quotes-only-reply",
    "client-without-max-tokens",
    "get-client-raises",
)

# Log canaries: distinctive words that may appear in no log record (casefolded).
_LOG_USER: Final = "Ocelot invoice reconciliation for Brienz"
_LOG_ASSISTANT: Final = "Kestrel summary: three invoices match the bank export."
_LOG_REPLY: Final = "Marmot supplier reconciliation"
_LOG_ERROR: Final = "Wombat provider detail 7731"
_LOG_RENAME: Final = "Pelican private rename"
_LOG_CANARIES: Final = ("ocelot", "brienz", "kestrel", "marmot", "wombat", "pelican")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats (``set_auto_title`` is new in GH-179: each test fails on its own)."""
    from admino import chats as module

    return module


@pytest.fixture()
def chat_titles() -> ModuleType:
    """admino.chat_titles, imported per test so each test fails on its own until it exists."""
    from admino import chat_titles as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture(autouse=True)
def retry_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the model policy's retry sleep with a recorder: no test really sleeps."""
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", _sleep)
    return slept


@dataclass(frozen=True)
class _Member:
    """A stored member and the TenantContext of their session."""

    user_id: uuid.UUID
    tenant: TenantContext


def _tenant(user_id: uuid.UUID, org_id: uuid.UUID) -> TenantContext:
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role="editor")
    return TenantContext.from_principal(principal)


def _member(db: FakeDb, *, org_id: uuid.UUID = ORG_ID) -> _Member:
    user_id = db.add_account(org_id=org_id, role="editor")
    return _Member(user_id, _tenant(user_id, org_id))


def _row(db: FakeDb, chat_id: uuid.UUID) -> dict[str, Any]:
    row = db.chat_row(chat_id)
    assert row is not None
    return row


def _title_of(db: FakeDb, chat_id: uuid.UUID) -> tuple[str, str]:
    row = _row(db, chat_id)
    return row["title"], row["title_source"]


def _chat_calls(db: FakeDb) -> list[Call]:
    return [call for call in db.calls if _CHAT_TABLE_RE.search(call.normalized)]


def _as_uuid(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return uuid.UUID(int=value.int)
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except ValueError:
            return None
    return None


def _bound_uuid(call: Call, pattern: str) -> uuid.UUID | None:
    """The UUID bound to the first ``<column> = $n`` the pattern finds in the call's SQL."""
    match = re.search(pattern, call.normalized)
    assert match is not None, f"no {pattern} predicate in: {call.normalized}"
    return _as_uuid(call.args[int(match.group(1)) - 1])


def _is_compare_and_set(call: Call) -> bool:
    """An UPDATE of chats guarded by the live, untitled, automatic predicates (S14)."""
    n = call.normalized
    where = n.split(" where ", 1)[1] if " where " in n else ""
    return (
        n.startswith("update chats ")
        and "deleted_at is null" in where
        and re.search(r"\btitle_source ?= ?'auto'", where) is not None
        and re.search(r"(?<![\w.])title ?= ?''", where) is not None
    )


def _log_dump(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record: formatted (exception traceback included) and raw."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(f"{formatter.format(record)}\n{vars(record)!r}" for record in caplog.records)


class _TitleClient:
    """Stand-in LLM client whose ``chat`` takes the per-call ``max_tokens`` (contract §1).

    Every call is recorded with its arguments; ``during`` runs while the reply
    is "being generated" (a concurrent rename or trash); then ``reply`` is
    returned as the content, or raised when it is an exception.
    """

    def __init__(
        self,
        reply: str | BaseException = _REPLY,
        *,
        provider: str = "infomaniak",
        during: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self.provider = provider
        self._reply = reply
        self._during = during
        self.calls: list[dict[str, Any]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append(
            {"messages": list(messages), "tools": tools, "stream": stream, "max_tokens": max_tokens}
        )
        if self._during is not None:
            await self._during()
        if isinstance(self._reply, BaseException):
            raise self._reply
        return LLMResponse(content=self._reply, model="title-model", done=True)


class _ClientWithoutMaxTokens:
    """A client whose ``chat`` predates the per-call cap: ``max_tokens`` is a TypeError."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        return LLMResponse(content="Legacy model title", done=True)


class _Resolver:
    """The ``get_client`` callable: returns the client, or raises ``error``; counts calls."""

    def __init__(self, client: object = None, *, error: BaseException | None = None) -> None:
        self._client = client
        self._error = error
        self.calls = 0

    def __call__(self) -> Any:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._client


class _RaisingPool:
    """An executor whose every statement raises ``error`` (a broken database)."""

    def __init__(self, error: BaseException) -> None:
        self._error = error
        self.calls = 0

    def _fail(self) -> Any:
        self.calls += 1
        raise self._error

    async def execute(self, query: str, *args: object) -> Any:
        return self._fail()

    async def fetch(self, query: str, *args: object) -> Any:
        return self._fail()

    async def fetchrow(self, query: str, *args: object) -> Any:
        return self._fail()

    async def fetchval(self, query: str, *args: object) -> Any:
        return self._fail()

    def acquire(self) -> Any:
        return self._fail()


async def _title_chat(
    chat_titles: ModuleType,
    pool: Any,
    tenant: TenantContext,
    chat_id: uuid.UUID,
    *,
    get_client: Callable[[], Any],
    user_message: str = _USER,
    assistant_message: str = _ASSISTANT,
    run_failed: bool = False,
    data_residency: bool = False,
    max_retries: int = 2,
) -> Any:
    return await chat_titles.title_chat(
        pool,
        tenant,
        chat_id,
        get_client=get_client,
        user_message=user_message,
        assistant_message=assistant_message,
        run_failed=run_failed,
        data_residency=data_residency,
        max_retries=max_retries,
    )


def _fallback_resolver(case: str) -> _Resolver:
    """The ``get_client`` of a fallback case (contract §3, generate_title / title_chat)."""
    if case == "llm-error":
        return _Resolver(_TitleClient(LLMError("No such model.", code="missing_model")))
    if case == "runtime-error":
        return _Resolver(_TitleClient(RuntimeError("SDK exploded")))
    if case == "empty-reply":
        return _Resolver(_TitleClient(""))
    if case == "quotes-only-reply":
        return _Resolver(_TitleClient('"" '))
    if case == "client-without-max-tokens":
        return _Resolver(_ClientWithoutMaxTokens())
    assert case == "get-client-raises"
    return _Resolver(error=AttributeError("'FakeAgent' object has no attribute '_llm'"))


# ---------------------------------------------------------------------------
# 1. chats.set_auto_title (contract §2, S14)
# ---------------------------------------------------------------------------


class TestSetAutoTitle:
    """The compare-and-set: only a live, untitled, automatic chat of the caller."""

    async def test_chats_set_auto_title_untitled_auto_chat_is_titled_and_returns_true(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The title is stored; title_source stays auto, last_activity_at and the rest
        of the row are unchanged."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST)
        before = _row(db, chat_id)

        result = await chats.set_auto_title(db.pool, alice.tenant, chat_id, _MODEL_TITLE)

        row = _row(db, chat_id)
        assert result is True
        assert (row["title"], row["title_source"], row["last_activity_at"]) == (
            _MODEL_TITLE,
            "auto",
            _PAST,
        )
        assert row == {**before, "title": _MODEL_TITLE}

    @pytest.mark.parametrize("case", _REFUSED_CASES)
    async def test_chats_set_auto_title_refused_chat_returns_false_and_changes_nothing(
        self, chats: ModuleType, db: FakeDb, case: str
    ) -> None:
        """A user title (even an empty one), an automatic title already set, a trashed
        chat, a colleague, the caller's id under another org, another org's chat and an
        unknown id: False, no ChatNotFoundError, every table unchanged."""
        alice, bob = _member(db), _member(db)
        carol = _member(db, org_id=OTHER_ORG_ID)
        untitled = db.add_chat(alice.user_id, created_at=_PAST)
        tenant, chat_id = alice.tenant, untitled
        if case == "user-titled":
            chat_id = db.add_chat(alice.user_id, title="Budget 2027", title_source="user")
        elif case == "user-titled-empty":
            chat_id = db.add_chat(alice.user_id, title="", title_source="user")
        elif case == "auto-titled":
            chat_id = db.add_chat(alice.user_id, title="Earlier automatic title")
        elif case == "trashed":
            chat_id = db.add_chat(alice.user_id, created_at=_PAST, deleted_at=_PAST)
        elif case == "other-owner":
            tenant = bob.tenant
        elif case == "other-org-tenant":
            tenant = _tenant(alice.user_id, OTHER_ORG_ID)
        elif case == "other-org-chat":
            chat_id = db.add_chat(carol.user_id, created_at=_PAST)
        else:
            assert case == "unknown"
            chat_id = _UNKNOWN_CHAT
        before = db.snapshot()

        result = await chats.set_auto_title(db.pool, tenant, chat_id, _MODEL_TITLE)

        assert result is False
        assert db.snapshot() == before

    async def test_chats_set_auto_title_is_one_scoped_compare_and_set_statement(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """One fetchval UPDATE of chats: the chat id, the caller's org and owner bound,
        ``deleted_at IS NULL``, ``title_source = 'auto'`` and ``title = ''`` stated, the
        title a bind parameter only."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        await chats.set_auto_title(db.pool, alice.tenant, chat_id, _MODEL_TITLE)

        (call,) = _chat_calls(db)
        assert call.method == "fetchval"
        assert _is_compare_and_set(call), call.normalized
        assert _bound_uuid(call, _ID_PARAM_RE) == chat_id
        assert _bound_uuid(call, ORG_ID_PARAM_RE) == ORG_ID
        assert _bound_uuid(call, _OWNER_PARAM_RE) == alice.user_id
        assert _MODEL_TITLE in call.args
        assert _MODEL_TITLE.lower() not in call.normalized

    async def test_chats_set_auto_title_writes_no_audit_event_and_no_log_line(
        self, chats: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An automatic title isn't in the audit catalog, and the repository logs nothing."""
        caplog.set_level(logging.DEBUG)
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        assert await chats.set_auto_title(db.pool, alice.tenant, chat_id, _MODEL_TITLE) is True

        assert db.audit == []
        assert db.matching(r"\baudit_events\b") == []
        assert [record for record in caplog.records if record.name.startswith("admino")] == []


# ---------------------------------------------------------------------------
# 2. chat_titles.title_chat: the model path
# ---------------------------------------------------------------------------


class TestTitleChatModel:
    """The chat's model titles the chat: one capped, tool-free request through the policy."""

    @pytest.mark.parametrize(
        ("provider", "data_residency"),
        [("infomaniak", True), ("anthropic", False)],
        ids=["swiss-provider-residency-org", "non-swiss-provider-no-residency"],
    )
    async def test_chat_titles_title_chat_stores_the_sanitized_model_title(
        self,
        chat_titles: ModuleType,
        db: FakeDb,
        provider: str,
        data_residency: bool,
    ) -> None:
        """The reply's first line without quotes or final period, as an auto title; the
        chat's activity untouched; title_chat returns None."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST)
        client = _TitleClient(_REPLY, provider=provider)

        result = await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(client),
            data_residency=data_residency,
        )

        row = _row(db, chat_id)
        assert result is None
        assert len(client.calls) == 1
        assert (row["title"], row["title_source"], row["last_activity_at"]) == (
            _MODEL_TITLE,
            "auto",
            _PAST,
        )

    async def test_chat_titles_title_chat_model_request_is_capped_without_tools_or_ids(
        self, chat_titles: ModuleType, db: FakeDb
    ) -> None:
        """get_client resolved once; one request: build_title_messages of the first
        exchange, no tools, max_tokens=TITLE_MAX_TOKENS (40); no chat, org or user id."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        client = _TitleClient(_REPLY)
        resolver = _Resolver(client)

        await _title_chat(chat_titles, db.pool, alice.tenant, chat_id, get_client=resolver)

        assert resolver.calls == 1
        (call,) = client.calls
        assert call["max_tokens"] == chat_titles.TITLE_MAX_TOKENS == 40
        assert not call["tools"]
        assert call["messages"] == chat_titles.build_title_messages(_USER, _ASSISTANT)
        sent = json.dumps([message.model_dump(mode="json") for message in call["messages"]])
        assert [ident for ident in (chat_id, ORG_ID, alice.user_id) if str(ident) in sent] == []

    async def test_chat_titles_title_chat_retries_within_the_platform_limit(
        self, chat_titles: ModuleType, db: FakeDb, retry_sleeps: list[float]
    ) -> None:
        """A transient error is retried max_retries times (llm_policy), then the fallback."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        client = _TitleClient(LLMError("Provider down.", code="provider_unavailable"))

        await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(client),
            max_retries=1,
        )

        assert (len(client.calls), len(retry_sleeps)) == (2, 1)
        assert _title_of(db, chat_id) == (_FALLBACK, "auto")

    @pytest.mark.parametrize("run_failed", [False, True], ids=["model-path", "failed-run"])
    async def test_chat_titles_title_chat_stores_through_one_compare_and_set(
        self, chat_titles: ModuleType, db: FakeDb, run_failed: bool
    ) -> None:
        """No read-then-write: the only chats statement is the scoped S14 UPDATE."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(_TitleClient(_REPLY)),
            run_failed=run_failed,
        )

        (call,) = _chat_calls(db)
        assert _is_compare_and_set(call), call.normalized
        assert (_bound_uuid(call, ORG_ID_PARAM_RE), _bound_uuid(call, _OWNER_PARAM_RE)) == (
            ORG_ID,
            alice.user_id,
        )
        assert _title_of(db, chat_id) == (_FALLBACK if run_failed else _MODEL_TITLE, "auto")


# ---------------------------------------------------------------------------
# 3. chat_titles.title_chat: the fallback and nothing to title
# ---------------------------------------------------------------------------


class TestTitleChatFallback:
    """The first message cut at a word boundary whenever the model gives no title."""

    @pytest.mark.parametrize("case", _FALLBACK_CASES)
    async def test_chat_titles_title_chat_without_a_model_title_stores_the_fallback(
        self, chat_titles: ModuleType, db: FakeDb, case: str
    ) -> None:
        """An LLMError, any other client error, an empty or unusable reply, a client
        without max_tokens, a get_client that raises: the fallback, as an auto title."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        result = await _title_chat(
            chat_titles, db.pool, alice.tenant, chat_id, get_client=_fallback_resolver(case)
        )

        assert result is None
        assert _title_of(db, chat_id) == (_FALLBACK, "auto")

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    async def test_chat_titles_title_chat_residency_org_non_swiss_provider_makes_no_call(
        self, chat_titles: ModuleType, db: FakeDb, provider: str
    ) -> None:
        """Residency on and the platform provider isn't infomaniak or vllm: no request
        reaches the client, the fallback title is stored."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        client = _TitleClient(_REPLY, provider=provider)

        await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(client),
            data_residency=True,
        )

        assert client.calls == []
        assert _title_of(db, chat_id) == (_FALLBACK, "auto")

    async def test_chat_titles_title_chat_failed_run_stores_fallback_without_a_client(
        self, chat_titles: ModuleType, db: FakeDb
    ) -> None:
        """run_failed: get_client is never called and no request is made."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        client = _TitleClient(_REPLY)
        resolver = _Resolver(client)

        result = await _title_chat(
            chat_titles, db.pool, alice.tenant, chat_id, get_client=resolver, run_failed=True
        )

        assert result is None
        assert (resolver.calls, client.calls) == (0, [])
        assert _title_of(db, chat_id) == (_FALLBACK, "auto")

    @pytest.mark.parametrize(
        ("run_failed", "reply"),
        [(True, _REPLY), (False, "")],
        ids=["failed-run", "empty-reply"],
    )
    async def test_chat_titles_title_chat_nothing_to_title_stores_nothing(
        self, chat_titles: ModuleType, db: FakeDb, run_failed: bool, reply: str
    ) -> None:
        """A whitespace-only first message and no model title: no UPDATE, the chat stays
        untitled and automatic."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        before = db.snapshot()
        db.calls.clear()

        result = await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(_TitleClient(reply)),
            user_message=_BLANK,
            run_failed=run_failed,
        )

        assert result is None
        assert db.matching(r"^update chats\b") == []
        assert db.snapshot() == before
        assert _title_of(db, chat_id) == ("", "auto")


# ---------------------------------------------------------------------------
# 4. chat_titles.title_chat: a user rename always wins
# ---------------------------------------------------------------------------


class TestTitleChatRenameRace:
    """Compare-and-set: a rename before or during generation is never overwritten."""

    @pytest.mark.parametrize(
        "reply",
        [_REPLY, LLMError("No such model.", code="missing_model")],
        ids=["model-title", "fallback-title"],
    )
    async def test_chat_titles_title_chat_rename_during_generation_wins(
        self, chats: ModuleType, chat_titles: ModuleType, db: FakeDb, reply: str | LLMError
    ) -> None:
        """A PATCH lands while the model is generating: the user's title stays, with
        title_source user, whichever title the task ends up with."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        async def rename() -> None:
            await chats.rename_chat(db.pool, alice.tenant, chat_id, _RENAME)

        client = _TitleClient(reply, during=rename)

        result = await _title_chat(
            chat_titles, db.pool, alice.tenant, chat_id, get_client=_Resolver(client)
        )

        assert result is None
        assert len(client.calls) == 1
        assert _title_of(db, chat_id) == (_RENAME, "user")

    @pytest.mark.parametrize("run_failed", [False, True], ids=["model-path", "failed-run"])
    async def test_chat_titles_title_chat_keeps_a_title_renamed_before_it_runs(
        self, chats: ModuleType, chat_titles: ModuleType, db: FakeDb, run_failed: bool
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        await chats.rename_chat(db.pool, alice.tenant, chat_id, _RENAME)
        before = db.snapshot()

        await _title_chat(
            chat_titles,
            db.pool,
            alice.tenant,
            chat_id,
            get_client=_Resolver(_TitleClient(_REPLY)),
            run_failed=run_failed,
        )

        assert db.snapshot() == before
        assert _title_of(db, chat_id) == (_RENAME, "user")

    async def test_chat_titles_title_chat_chat_trashed_during_generation_gets_no_title(
        self, chats: ModuleType, chat_titles: ModuleType, db: FakeDb
    ) -> None:
        """The chat goes to the trash while the model is generating: nothing is stored,
        no exception."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        async def trash() -> None:
            await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=None)

        client = _TitleClient(_REPLY, during=trash)

        result = await _title_chat(
            chat_titles, db.pool, alice.tenant, chat_id, get_client=_Resolver(client)
        )

        row = _row(db, chat_id)
        assert result is None
        assert len(client.calls) == 1
        assert (row["title"], row["title_source"]) == ("", "auto")
        assert row["deleted_at"] is not None


# ---------------------------------------------------------------------------
# 5. chat_titles.title_chat: tenant isolation and failures
# ---------------------------------------------------------------------------


class TestTitleChatScopeAndFailures:
    """Another member's or org's tenant changes nothing; nothing but MemoryError and
    RecursionError escapes."""

    @pytest.mark.parametrize("case", ["other-owner", "other-org"])
    async def test_chat_titles_title_chat_foreign_tenant_changes_nothing(
        self, chat_titles: ModuleType, db: FakeDb, case: str
    ) -> None:
        """A colleague's or another org's tenant naming Alice's untitled chat."""
        alice, bob = _member(db), _member(db)
        carol = _member(db, org_id=OTHER_ORG_ID)
        chat_id = db.add_chat(alice.user_id)
        tenant = bob.tenant if case == "other-owner" else carol.tenant
        before = db.snapshot()

        result = await _title_chat(
            chat_titles, db.pool, tenant, chat_id, get_client=_Resolver(_TitleClient(_REPLY))
        )

        assert result is None
        assert db.snapshot() == before

    @pytest.mark.parametrize("run_failed", [False, True], ids=["model-path", "failed-run"])
    @pytest.mark.parametrize(
        "error",
        [
            asyncpg.exceptions.CheckViolationError("Failing row contains (secret)"),
            RuntimeError("pool is closed"),
        ],
        ids=["postgres-error", "runtime-error"],
    )
    async def test_chat_titles_title_chat_database_error_is_swallowed(
        self, chat_titles: ModuleType, db: FakeDb, error: Exception, run_failed: bool
    ) -> None:
        """The store fails: title_chat returns None (the background task never raises)."""
        alice = _member(db)
        pool = _RaisingPool(error)

        result = await _title_chat(
            chat_titles,
            pool,
            alice.tenant,
            uuid.uuid4(),
            get_client=_Resolver(_TitleClient(_REPLY)),
            run_failed=run_failed,
        )

        assert result is None
        assert pool.calls >= 1

    @pytest.mark.parametrize("error_type", [MemoryError, RecursionError])
    async def test_chat_titles_title_chat_memory_and_recursion_errors_propagate(
        self, chat_titles: ModuleType, db: FakeDb, error_type: type[BaseException]
    ) -> None:
        """Only MemoryError and RecursionError escape (RecursionError is a RuntimeError);
        nothing is stored."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        before = db.snapshot()

        with pytest.raises(error_type):
            await _title_chat(
                chat_titles,
                db.pool,
                alice.tenant,
                chat_id,
                get_client=_Resolver(_TitleClient(error_type())),
            )

        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 6. chat_titles.title_chat: content-free logs
# ---------------------------------------------------------------------------


class TestTitleChatLogs:
    """Every outcome logs the chat id; nothing logs content, exception text or other ids."""

    async def test_chat_titles_title_chat_logs_no_title_message_reply_or_error_text(
        self,
        chats: ModuleType,
        chat_titles: ModuleType,
        db: FakeDb,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The model, fallback (LLMError with a cause, retried error, RuntimeError,
        get_client failure), failed-run, rename-race, trashed and database-failure paths,
        at DEBUG: no record (message, args, exception info) holds a canary, the org id or
        the user id; each chat id appears in an admino record."""
        caplog.set_level(logging.DEBUG)
        alice = _member(db)
        chat_ids: list[uuid.UUID] = []

        async def run(
            get_client: Callable[[], Any],
            *,
            pool: Any = None,
            chat_id: uuid.UUID | None = None,
            run_failed: bool = False,
        ) -> uuid.UUID:
            if chat_id is None:
                chat_id = db.add_chat(alice.user_id)
            chat_ids.append(chat_id)
            await _title_chat(
                chat_titles,
                db.pool if pool is None else pool,
                alice.tenant,
                chat_id,
                get_client=get_client,
                user_message=_LOG_USER,
                assistant_message=_LOG_ASSISTANT,
                run_failed=run_failed,
            )
            return chat_id

        caused = LLMError(f"Model refused: {_LOG_ERROR}", code="missing_model")
        caused.__cause__ = RuntimeError(f"upstream body: {_LOG_ERROR}")
        titled = await run(_Resolver(_TitleClient(_LOG_REPLY)))
        fallback = await run(_Resolver(_TitleClient(caused)))
        await run(_Resolver(_TitleClient(LLMError(_LOG_ERROR, code="provider_unavailable"))))
        await run(_Resolver(_TitleClient(RuntimeError(_LOG_ERROR))))
        await run(_Resolver(error=AttributeError(_LOG_ERROR)))
        await run(_Resolver(_TitleClient(_LOG_REPLY)), run_failed=True)

        raced = db.add_chat(alice.user_id)

        async def rename() -> None:
            await chats.rename_chat(db.pool, alice.tenant, raced, _LOG_RENAME)

        await run(_Resolver(_TitleClient(_LOG_REPLY, during=rename)), chat_id=raced)

        trashed = db.add_chat(alice.user_id)

        async def trash() -> None:
            await chats.trash_chat(db.pool, alice.tenant, trashed, ip=None)

        await run(_Resolver(_TitleClient(_LOG_REPLY, during=trash)), chat_id=trashed)
        for error in (
            asyncpg.exceptions.CheckViolationError(f"Failing row contains ({_LOG_ERROR})"),
            RuntimeError(_LOG_ERROR),
        ):
            await run(
                _Resolver(_TitleClient(_LOG_REPLY)), pool=_RaisingPool(error), chat_id=uuid.uuid4()
            )

        # The scenarios reached their paths (the scan below isn't vacuous).
        assert _title_of(db, titled)[0].startswith("Marmot")
        assert _title_of(db, fallback)[0].startswith("Ocelot")
        assert _title_of(db, raced) == (_LOG_RENAME, "user")
        dump = _log_dump(caplog).casefold()
        leaked = [
            marker
            for marker in (*_LOG_CANARIES, str(ORG_ID), str(alice.user_id))
            if marker.casefold() in dump
        ]
        assert leaked == []
        admino_lines = [
            record.getMessage() for record in caplog.records if record.name.startswith("admino")
        ]
        unlogged = [
            chat_id
            for chat_id in chat_ids
            if not any(str(chat_id) in line for line in admino_lines)
        ]
        assert unlogged == []
