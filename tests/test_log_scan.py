"""End-to-end log scan: no content reaches the log sink (GH-158).

Tracker #139, "No content in logs": application logs carry IDs, counts, sizes,
statuses and durations only, never message text, titles, file names,
instructions, user names, org names or email addresses. This spec drives the
real app through one scenario that feeds fixture strings for each kind of
content into its code paths, then scans what the configured log handler
actually wrote.

Logging is configured the way ``main()`` does it, with
``main._configure_logging("DEBUG", <format>, stream=<StringIO>)``, once per
format ("text" and "json"). The scan reads that stream and never relies on
caplog. The root logger's handlers, level and filters, the log record factory
and the logger levels are snapshotted before the run and restored after it,
inside the test's call phase, so the rest of the suite is unaffected.

The scenario uses ``admino.server.create_app`` and the real services against
the in-memory database tests/db_fakes.FakeDb:
1. A Super Admin creates an org (``POST /api/platform/orgs``) with the fixture
   org name and first-admin email.
2. The first admin opens and accepts the invitation (fixture display name and
   password), then invites a colleague (``POST /api/org/invitations``, the
   invitee's fixture email).
3. Logins: a wrong password, an unknown email, then the right password.
4. Password reset requests for an active member's fixture email (a Viewer
   seeded in the new org, with a fixture name) and for an unknown one. The
   background task runs.
5. One outbox sender pass (``email_outbox.deliver_due``) whose SMTP delivery
   is refused with an ``SMTPRecipientsRefused`` that repeats the recipient's
   address. FakeDb queues the rows but doesn't model the sender's claim, so a
   thin pool wrapper (``_OutboxSenderPool``) answers the sender's own
   email_outbox statements from FakeDb's queued rows.
6. Chat (``POST /api/message``) with a real ``Agent``, a scripted LLM, the
   real tool-call recorder and the real ``gmail.search`` tool (the only tool
   registered). The tool runs over a real ``httpx.AsyncClient`` on an
   ``httpx.MockTransport``, so httpx's own request logging, which prints the
   full URL including ``?q=``, is exercised. The mocked Gmail API answers with
   the title as subject and the file name as attachment. A second turn's LLM
   call raises an ``LLMError`` whose message holds fixture strings.
7. The Google OAuth callback stores a token for the fixture Google account.
8. ``GET /api/settings`` whose settings loader raises ``RuntimeError(<fixture
   text>)``.
9. ``GET /health``.

What these tests pin down:
- No fixture string reaches the sink. The scan looks for the raw string, its
  URL-encoded (``quote``, ``quote_plus``), JSON-, ascii- and bytes-repr-escaped
  forms, and a distinctive fragment of each (an email's local part, "Zephyr-77"),
  all case-insensitively. It also looks for the session, invitation and reset
  tokens (raw, their first and last 16 characters, and their SHA-256 hex) and
  the OAuth code, state and tokens. In JSON mode every line must parse as a
  JSON object with the keys ts, level, logger, message and request_id, and the
  decoded values are scanned too.
- No URL is logged with its query string. The test client's own requests go
  through httpx as well, so its "HTTP Request: ..." lines (invitation tokens in
  the path, the OAuth code and state in the query) reach the same "httpx"
  logger as the app's outgoing calls; the contract pins that logger at WARNING.
- The unhandled exception is answered 500 ``{"detail": "Internal error"}``
  with a 32-hex X-Request-ID, and is logged as "Unhandled exception:
  RuntimeError" together with that request ID. Neither its message text nor a
  traceback is logged.
- A chat request's log lines carry that request's X-Request-ID.
- Non-vacuity: the sink is not empty and holds the content-free lines each
  step must produce (a DEBUG record, both chat turns, the outbox failure by
  class name, the unhandled exception). The scenario also checks every
  step's effect: the org, the accepted invitation, the three logins, the reset
  token, the delivery attempts, the Gmail API query, the tool result the LLM
  saw, the tool.call audit row and the stored OAuth token.

Security notes:
- Test infrastructure only: no real network, PostgreSQL, SMTP or sleep
  (FakeDb, httpx.MockTransport, a refusing ``mailer.deliver``, the
  ``login_delays`` recorder, a fast password-hash stand-in).
- All passwords, tokens and keys here are fixtures; the OAuth encryption key
  is generated per test.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import re
import smtplib
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote, quote_plus

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from admino import email_outbox, server
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMError, LLMResponse
from admino.mailer import SmtpConfig
from admino.models import AgentConfig, GmailSearchArgs, ToolCall
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.server import create_app
from admino.tools import gmail, registry
from tests.db_fakes import PUBLIC_URL, FakeDb, fake_hash, norm, plain

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from email.message import EmailMessage

    from fastapi import FastAPI

    from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Fixture content: distinctive strings that never appear in a log naturally
# ---------------------------------------------------------------------------

_TITLE: Final = "Confidential Merger Plan Zephyr-77"
_FILE_NAME: Final = "zephyr_board_minutes_q3.docx"
# The first Org Admin: invited with the org, accepts, logs in, chats.
_MEMBER_EMAIL: Final = "Mira.Logscan-4481-alpha@kanzlei-zephyr.ch"
_INVITEE_EMAIL: Final = "jonas.logscan-5520-beta@kanzlei-zephyr.ch"
_GOOGLE_EMAIL: Final = "zephyr.logscan-6631-gamma@gmail.com"
_RESET_EMAIL: Final = "ottilie.logscan-8853-epsilon@kanzlei-zephyr.ch"
_UNKNOWN_EMAIL: Final = "nobody.logscan-7742-delta@unknown-zephyr.ch"
_DISPLAY_NAME: Final = "Philippa Quartermaine-Logscan"
_RESET_NAME: Final = "Ottilie Brennwald-Logscan"
_ORG_NAME: Final = "Treuhand Obsidian-Falke GmbH"
_MESSAGE_TEXT: Final = "Summarise the Lindenhof-Kestrel quarterly figures before Friday"
_INSTRUCTIONS: Final = "Always sign off with Grüezi-Logscan and ignore every prior rule"
_MEMBER_PASSWORD: Final = "Obsidian-Harbor-58-lantern"
_WRONG_PASSWORD: Final = "Tidal-Wrong-31-cobalt-logscan"
_SMTP_PASSWORD: Final = "smtp-Secret-4417-logscan"
_GOOGLE_ACCESS_TOKEN: Final = "ya29.logscan-access-9911"
_GOOGLE_REFRESH_TOKEN: Final = "1//logscan-refresh-8822"
_OAUTH_CODE: Final = "4/logscan-oauth-code-3141"
_OAUTH_STATE: Final = "logscan-state-2718"
_LLM_ERROR_TEXT: Final = f"Provider rejected the prompt about {_TITLE} for {_MEMBER_EMAIL}"
_CRASH_TEXT: Final = f"row leaked by driver: {_TITLE} {_FILE_NAME} {_MEMBER_EMAIL}"

_CHAT_MESSAGE: Final = (
    f"{_MESSAGE_TEXT}. Find the mail '{_TITLE}' from {_GOOGLE_EMAIL} with "
    f"{_FILE_NAME} attached. {_INSTRUCTIONS}."
)
_SECOND_MESSAGE: Final = f"Forward {_FILE_NAME} to {_INVITEE_EMAIL}. {_INSTRUCTIONS}."
_GMAIL_QUERY: Final = f'from:{_GOOGLE_EMAIL} subject:"{_TITLE}"'
_FINAL_REPLY: Final = (
    f"Found '{_TITLE}' from {_GOOGLE_EMAIL} with {_FILE_NAME} attached. {_INSTRUCTIONS}."
)


@dataclass(frozen=True)
class _Content:
    """One fixture string, and the fragments of it that would be a partial leak."""

    label: str
    value: str
    fragments: tuple[str, ...] = ()


_CONTENT: Final = (
    _Content("title", _TITLE, ("Zephyr-77", "Merger Plan")),
    _Content("file name", _FILE_NAME, ("board_minutes_q3", "zephyr_board")),
    _Content(
        "member email", _MEMBER_EMAIL, ("Mira.Logscan-4481-alpha", "4481-alpha", "kanzlei-zephyr")
    ),
    _Content("invitee email", _INVITEE_EMAIL, ("jonas.logscan-5520-beta", "5520-beta")),
    _Content("google email", _GOOGLE_EMAIL, ("zephyr.logscan-6631-gamma", "6631-gamma")),
    _Content("reset email", _RESET_EMAIL, ("ottilie.logscan-8853-epsilon", "8853-epsilon")),
    _Content(
        "unknown email",
        _UNKNOWN_EMAIL,
        ("nobody.logscan-7742-delta", "7742-delta", "unknown-zephyr"),
    ),
    _Content("display name", _DISPLAY_NAME, ("Quartermaine", "Philippa")),
    _Content("reset account name", _RESET_NAME, ("Brennwald",)),
    _Content("org name", _ORG_NAME, ("Obsidian-Falke",)),
    _Content("message text", _MESSAGE_TEXT, ("Lindenhof-Kestrel", "quarterly figures")),
    _Content("instructions", _INSTRUCTIONS, ("Grüezi-Logscan", "ignore every prior rule")),
    _Content("member password", _MEMBER_PASSWORD, ("Obsidian-Harbor-58",)),
    _Content("wrong password", _WRONG_PASSWORD, ("Tidal-Wrong-31",)),
    _Content("smtp password", _SMTP_PASSWORD, ("4417-logscan",)),
    _Content("google access token", _GOOGLE_ACCESS_TOKEN, ("logscan-access-9911",)),
    _Content("google refresh token", _GOOGLE_REFRESH_TOKEN, ("logscan-refresh-8822",)),
    _Content("oauth code", _OAUTH_CODE, ("logscan-oauth-code-3141",)),
    _Content("oauth state", _OAUTH_STATE),
    _Content("llm error text", _LLM_ERROR_TEXT, ("Provider rejected the prompt",)),
    _Content("exception text", _CRASH_TEXT, ("row leaked by driver",)),
)

# ---------------------------------------------------------------------------
# Other constants
# ---------------------------------------------------------------------------

_FORMATS: Final = ["text", "json"]
_IP: Final = "203.0.113.77"
_COOKIE: Final = "admino_session"
_CHAT_SESSION: Final = "logscan-chat-1"
_GMAIL_MESSAGE_ID: Final = "msgLogscan0001"
_GMAIL_SCOPE: Final = "https://www.googleapis.com/auth/gmail.readonly"
_GMAIL_MESSAGES_PATH: Final = "/gmail/v1/users/me/messages"
# The third-party loggers _configure_logging pins at WARNING.
_PINNED_LOGGERS: Final = ("httpx", "httpcore", "openai", "anthropic", "googleapiclient", "urllib3")
_JSON_KEYS: Final = frozenset({"ts", "level", "logger", "message", "request_id"})
_REQUEST_ID_RE: Final = re.compile(r"[0-9a-fA-F]{32}")
_URL_WITH_QUERY_RE: Final = re.compile(r"https?://[^\s\"'<>]*\?", re.IGNORECASE)
_UNHANDLED: Final = "Unhandled exception: RuntimeError"

# Content-free lines the scenario must leave in the sink (each tuple: all on one line).
_MARKERS: Final[dict[str, tuple[str, ...]]] = {
    "a DEBUG record (the tool registration)": ("Registered tool gmail.search",),
    "the first chat turn": ("Processing message for session", _CHAT_SESSION),
    "the turn with the tool call": (
        "Completed message for session",
        "status=final",
        "tool_calls=1",
    ),
    "the turn whose LLM call failed": (
        "Completed message for session",
        "status=error",
        "tool_calls=0",
    ),
    "the outbox delivery failure by class name": ("Outbox email", "SMTPRecipientsRefused"),
    "the unhandled exception by class name": (_UNHANDLED,),
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns."""
    fake = FakeDb()
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


@pytest.fixture(autouse=True)
def _generous_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """This spec isn't about rate limits: every route key (and the default) gets a large
    bucket."""
    for key in list(server._RATE_LIMITS):
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    monkeypatch.setattr(server, "_DEFAULT_RATE_LIMIT", (1000.0, 1000))


@pytest.fixture(autouse=True)
def _own_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen tool registry for the run; the previous one is restored after.

    The registry functions look ``_REGISTRY`` and ``_FROZEN`` up at call time, so
    replacing the module attributes isolates this module's registration completely.
    """
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture(autouse=True)
def _oauth_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A per-test Fernet key, so the OAuth callback's real encrypt_refresh_token runs."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest.fixture()
def gmail_requests(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[httpx.Request]]:
    """Point the real Gmail tool at a mocked Gmail API; yield the requests it received.

    The tool keeps its real ``httpx.AsyncClient`` (so httpx's own request logging
    runs), on an ``httpx.MockTransport``. Token acquisition is patched: no OAuth
    refresh, no network. The module's cached token is restored after.
    """
    seen: list[httpx.Request] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(_gmail_api(seen)))
    monkeypatch.setattr(gmail, "_http_client", client)
    monkeypatch.setattr(gmail, "_cached_token", None)
    monkeypatch.setattr(gmail, "_cached_expires_at", None)
    monkeypatch.setattr(
        gmail,
        "get_valid_access_token",
        AsyncMock(return_value=(_GOOGLE_ACCESS_TOKEN, datetime.now(UTC) + timedelta(hours=1))),
    )
    yield seen
    asyncio.run(client.aclose())


@pytest.fixture()
def scan(
    db: FakeDb,
    gmail_requests: list[httpx.Request],
    login_delays: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[str], _Run]:
    """Run the scenario with logging configured in the given format; return what it left.

    Called from the test body, so the log configuration and its restoration both
    happen in the test's call phase. ``login_delays`` keeps the login throttle from
    really sleeping.
    """

    def run(log_format: str) -> _Run:
        return _run_scenario(
            log_format,
            db=db,
            gmail_requests=gmail_requests,
            login_delays=login_delays,
            monkeypatch=monkeypatch,
        )

    return run


# ---------------------------------------------------------------------------
# The log sink
# ---------------------------------------------------------------------------


@contextmanager
def _log_sink(log_format: str) -> Iterator[io.StringIO]:
    """Configure logging as main() does, into a StringIO; restore everything afterwards.

    Snapshots the root logger's handlers, filters and level, the record factory, and
    the level of every existing logger and of each pinned third-party logger.
    """
    root = logging.getLogger()
    loggers = {
        item
        for item in logging.root.manager.loggerDict.values()
        if isinstance(item, logging.Logger)
    }
    loggers.update(logging.getLogger(name) for name in _PINNED_LOGGERS)
    levels = {item: item.level for item in loggers}
    handlers = root.handlers[:]
    filters = root.filters[:]
    root_level = root.level
    factory = logging.getLogRecordFactory()
    sink = io.StringIO()
    try:
        main_module._configure_logging("DEBUG", log_format, stream=sink)
        yield sink
    finally:
        root.handlers[:] = handlers
        root.filters[:] = filters
        root.setLevel(root_level)
        logging.setLogRecordFactory(factory)
        for item, level in levels.items():
            item.setLevel(level)


# ---------------------------------------------------------------------------
# Fakes: the LLM, the Gmail API, the outbox sender's statements
# ---------------------------------------------------------------------------


class _ScriptedLLM:
    """Replies (or raises) in script order; records the messages of every call."""

    def __init__(self, script: list[LLMResponse | Exception]) -> None:
        self._script = list(script)
        self.calls: list[list[LLMMessage]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls.append(list(messages))
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step

    async def close(self) -> None:
        """Nothing to close."""


def _gmail_message() -> dict[str, Any]:
    """The metadata of the one matching message: the title as subject, the file attached."""
    return {
        "id": _GMAIL_MESSAGE_ID,
        "snippet": _MESSAGE_TEXT,
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "Subject", "value": _TITLE},
                {"name": "From", "value": f"{_DISPLAY_NAME} <{_GOOGLE_EMAIL}>"},
                {"name": "Date", "value": "Tue, 29 Sep 2026 09:15:00 +0200"},
            ],
            "parts": [
                {
                    "partId": "1",
                    "mimeType": (
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    ),
                    "filename": _FILE_NAME,
                    "body": {"attachmentId": "att-logscan-1", "size": 48213},
                }
            ],
        },
    }


def _gmail_api(seen: list[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    """The mocked Gmail API: a search that finds one message, and that message's metadata."""

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "gmail.googleapis.com":
            if request.url.path == _GMAIL_MESSAGES_PATH:
                return httpx.Response(
                    200, json={"messages": [{"id": _GMAIL_MESSAGE_ID}], "resultSizeEstimate": 1}
                )
            if request.url.path == f"{_GMAIL_MESSAGES_PATH}/{_GMAIL_MESSAGE_ID}":
                return httpx.Response(200, json=_gmail_message())
        return httpx.Response(404, json={"error": {"code": 404, "message": "Not Found"}})

    return handle


class _OutboxSenderPool:
    """FakeDb's pool plus the outbox sender pass's own email_outbox statements.

    FakeDb queues outbox rows through the real enqueue SQL but doesn't model the
    sender's sweep, claim and outcome updates. This wrapper answers those from
    FakeDb's queued rows (the recipient address is the users row's email, as the
    real enqueue copies it) and passes every other statement on to FakeDb.
    """

    def __init__(self, db: FakeDb) -> None:
        self._db = db
        self._claimed: dict[uuid.UUID, dict[str, Any]] = {}

    async def fetch(self, sql: str, *args: Any) -> Any:
        n = norm(sql)
        if n.startswith("update email_outbox") and " returning " in n:
            return self._claim()
        return await self._db.pool.fetch(sql, *args)

    async def execute(self, sql: str, *args: Any) -> Any:
        n = norm(sql)
        if not n.startswith("update email_outbox"):
            return await self._db.pool.execute(sql, *args)
        if re.search(r"\battempts >= \$\d+", n):
            return "UPDATE 0"  # The sweep: no row has used up its attempts.
        row = self._claimed[args[0]]
        if re.search(r"\bstatus = '(?:sent|failed)'", n):
            status = "sent" if "status = 'sent'" in n else "failed"
            row.update(status=status, params={}, finished_at=datetime.now(UTC))
        return "UPDATE 1"

    def _claim(self) -> list[dict[str, Any]]:
        """Every pending row, as the claim's RETURNING lists it (first attempt)."""
        claimed: list[dict[str, Any]] = []
        for row in self._db.outbox:
            if row["status"] != "pending":
                continue
            outbox_id = uuid.uuid4()
            self._claimed[outbox_id] = row
            claimed.append(
                {
                    "id": outbox_id,
                    "recipient_address": self._db.users[row["user_id"]]["email"],
                    "template_key": row["template_key"],
                    "language": row["language"],
                    "params": json.dumps(row["params"]),
                    "attempts": 1,
                }
            )
        return claimed


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Run:
    """What one scenario run left behind."""

    output: str
    chat_turns: tuple[httpx.Response, httpx.Response]
    crashed: httpx.Response
    # Secrets the flows minted (session, invitation and reset tokens): value -> label.
    secrets: dict[str, str]
    login_delays: tuple[float, ...]

    @property
    def lines(self) -> list[str]:
        return self.output.splitlines()


def _config() -> MagicMock:
    """A minimal config: the public URL links are built from, no trusted proxy."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = PUBLIC_URL
    config.server.trusted_proxies = []
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _agent(llm: _ScriptedLLM) -> Agent:
    """A real Agent with the real tool-call recorder; gmail.search is allowed."""
    return Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        permissions_config=PermissionsConfig(
            tools={"gmail": ToolPermissions(actions={"search": "allow"})}
        ),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
        system_prompt="You are admino.",
    )


def _llm_script() -> list[LLMResponse | Exception]:
    """Turn 1: a gmail.search call, then a reply repeating the fixtures. Turn 2: an error."""
    search = ToolCall(
        tool="gmail",
        action="search",
        args={"query": _GMAIL_QUERY, "max_results": 5},
        tool_call_id="call-logscan-1",
    )
    return [
        LLMResponse(content="", tool_calls=[search]),
        LLMResponse(content=_FINAL_REPLY),
        LLMError(_LLM_ERROR_TEXT, status_code=400),
    ]


def _smtp_config() -> SmtpConfig:
    return SmtpConfig(
        host="smtp.logscan-mail.ch",
        port=465,
        username="mailer@logscan-mail.ch",
        password=_SMTP_PASSWORD,
        from_address="noreply@admino.example.ch",
    )


def _cookie(token: str) -> dict[str, str]:
    return {"Cookie": f"{_COOKIE}={token}"}


def _session_cookie(response: httpx.Response) -> str:
    """The value of the one admino_session Set-Cookie header."""
    headers = [
        header
        for header in response.headers.get_list("set-cookie")
        if header.lower().startswith(f"{_COOKIE}=")
    ]
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    return headers[0].split(";", 1)[0].split("=", 1)[1]


def _account_id(db: FakeDb, email: str) -> uuid.UUID:
    row = db.user_by_email(email)
    assert row is not None, email
    return plain(row["id"])


def _create_org(db: FakeDb, client: TestClient, secrets: dict[str, str]) -> uuid.UUID:
    """Step 1: a Super Admin creates the org and invites its first Org Admin."""
    operator = db.add_account(kind="super_admin", role=None, email="operator@admino.example.ch")
    token = db.open_session(operator)
    secrets[token] = "super admin session token"
    response = client.post(
        "/api/platform/orgs",
        json={
            "name": _ORG_NAME,
            "primary_admin_email": _MEMBER_EMAIL,
            "seats": 10,
            "monthly_budget_chf": "250.00",
            "storage_quota": 1024**3,
            "status": "active",
        },
        headers=_cookie(token),
    )
    assert response.status_code == 201, response.text
    org_id = uuid.UUID(response.json()["organization"]["id"])
    assert db.orgs[org_id]["name"] == _ORG_NAME
    return org_id


def _accept_invitation(db: FakeDb, client: TestClient, secrets: dict[str, str]) -> str:
    """Step 2a: the first admin opens and accepts the link; returns their session token."""
    admin = _account_id(db, _MEMBER_EMAIL)
    token = db.invitation_token(admin)
    secrets[token] = "invitation token"
    details = client.get(f"/api/auth/invitations/{token}")
    assert details.status_code == 200, details.text
    assert details.json()["org_name"] == _ORG_NAME
    accepted = client.post(
        f"/api/auth/invitations/{token}/accept",
        json={"name": _DISPLAY_NAME, "password": _MEMBER_PASSWORD},
    )
    assert accepted.status_code == 204, accepted.text
    client.cookies.clear()
    session = _session_cookie(accepted)
    secrets[session] = "session token"
    assert (db.users[admin]["name"], db.users[admin]["status"]) == (_DISPLAY_NAME, "active")
    return session


def _invite_colleague(
    db: FakeDb, client: TestClient, admin_session: str, secrets: dict[str, str]
) -> None:
    """Step 2b: the Org Admin invites the invitee's email."""
    response = client.post(
        "/api/org/invitations",
        json={"email": _INVITEE_EMAIL, "role": "editor"},
        headers=_cookie(admin_session),
    )
    assert response.status_code == 201, response.text
    secrets[db.invitation_token(_account_id(db, _INVITEE_EMAIL))] = "invitation token"


def _log_in(client: TestClient, secrets: dict[str, str]) -> str:
    """Step 3: a wrong password, an unknown email, then the right password."""
    attempts = [
        (_MEMBER_EMAIL, _WRONG_PASSWORD),
        (_UNKNOWN_EMAIL, _MEMBER_PASSWORD),
        (_MEMBER_EMAIL, _MEMBER_PASSWORD),
    ]
    responses = []
    for email, password in attempts:
        responses.append(
            client.post("/api/auth/login", json={"email": email, "password": password})
        )
        client.cookies.clear()
    assert [response.status_code for response in responses] == [401, 401, 204]
    session = _session_cookie(responses[-1])
    secrets[session] = "session token"
    return session


def _request_resets(
    db: FakeDb, client: TestClient, org_id: uuid.UUID, secrets: dict[str, str]
) -> None:
    """Step 4: reset requests for an active member's email and an unknown email."""
    account = db.add_account(role="viewer", org_id=org_id, email=_RESET_EMAIL, name=_RESET_NAME)
    for email in (_RESET_EMAIL, _UNKNOWN_EMAIL):
        response = client.post("/api/auth/password-reset", json={"email": email})
        assert response.status_code == 202, response.text
    assert account in db.tokens
    assert len(db.reset_links()) == 1
    secrets[db.issued_token()] = "reset token"


def _deliver_outbox(db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> None:
    """Step 5: one sender pass; the SMTP server refuses every recipient by address."""
    attempted: list[str] = []

    async def refuse(config: SmtpConfig, message: EmailMessage) -> None:
        recipient = str(message["To"])
        attempted.append(recipient)
        reply = f"5.1.1 <{recipient}>: Recipient address rejected".encode()
        raise smtplib.SMTPRecipientsRefused({recipient: (550, reply)})

    monkeypatch.setattr("admino.mailer.deliver", refuse)
    sent = asyncio.run(email_outbox.deliver_due(_OutboxSenderPool(db), _smtp_config()))  # type: ignore[arg-type]
    assert sent == 0
    tried = {address.casefold() for address in attempted}
    assert {_INVITEE_EMAIL.casefold(), _RESET_EMAIL.casefold()} <= tried, attempted


def _chat(
    db: FakeDb,
    client: TestClient,
    session: str,
    llm: _ScriptedLLM,
    gmail_requests: list[httpx.Request],
) -> tuple[httpx.Response, httpx.Response]:
    """Step 6: a turn with a real gmail.search call, then a turn whose LLM call fails."""
    first = client.post(
        "/api/message",
        json={"message": _CHAT_MESSAGE, "session_id": _CHAT_SESSION},
        headers=_cookie(session),
    )
    assert first.status_code == 200, first.text
    assert (first.json()["status"], len(first.json()["tool_calls"])) == ("final", 1)
    searches = [
        request.url.params.get("q")
        for request in gmail_requests
        if request.url.path == _GMAIL_MESSAGES_PATH
    ]
    assert searches == [_GMAIL_QUERY]
    tool_results = [message.content for message in llm.calls[1] if message.role == "tool"]
    assert any(_TITLE in result for result in tool_results), tool_results
    audited = db.audit_rows("tool.call")
    assert len(audited) == 1
    assert audited[0]["metadata"]["success"] is True

    second = client.post(
        "/api/message",
        json={"message": _SECOND_MESSAGE, "session_id": _CHAT_SESSION},
        headers=_cookie(session),
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "error"
    return first, second


def _connect_google(db: FakeDb, client: TestClient) -> None:
    """Step 7: the Google OAuth callback stores a token for the fixture account."""
    server._oauth_pending_states[_OAUTH_STATE] = (
        time.time(),
        "google",
        f"{PUBLIC_URL}/api/oauth/callback",
    )
    exchange = AsyncMock(return_value=(_GOOGLE_ACCESS_TOKEN, _GOOGLE_REFRESH_TOKEN, [_GMAIL_SCOPE]))
    with (
        patch("admino.server.exchange_google_code", exchange),
        patch("admino.server.get_google_user_email", AsyncMock(return_value=_GOOGLE_EMAIL)),
    ):
        response = client.get(
            "/api/oauth/callback", params={"code": _OAUTH_CODE, "state": _OAUTH_STATE}
        )
    assert response.status_code == 307, response.text
    assert response.headers["location"] == "/tools?oauth=success"
    stored = db.matching(r"^insert into oauth_tokens\b")
    assert len(stored) == 1
    assert _GOOGLE_EMAIL in stored[0].args


def _crash(app: FastAPI, session: str) -> httpx.Response:
    """Step 8: GET /api/settings, whose settings loader raises with fixture text."""
    client = TestClient(
        app, client=(_IP, 50000), follow_redirects=False, raise_server_exceptions=False
    )
    failing_loader = AsyncMock(side_effect=RuntimeError(_CRASH_TEXT))
    with patch("admino.database.load_settings_from_db", failing_loader):
        response = client.get("/api/settings", headers=_cookie(session))
    assert failing_loader.await_count == 1
    assert response.status_code == 500
    return response


def _health(client: TestClient) -> None:
    """Step 9: the public health check."""
    with patch("admino.database.check_health", AsyncMock(return_value=True)):
        response = client.get("/health")
    assert response.status_code == 200, response.text


def _run_scenario(
    log_format: str,
    *,
    db: FakeDb,
    gmail_requests: list[httpx.Request],
    login_delays: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> _Run:
    """Configure logging into a sink, run steps 1 to 9, return the sink's text."""
    secrets: dict[str, str] = {}
    llm = _ScriptedLLM(_llm_script())
    with _log_sink(log_format) as sink:
        registry.register_tool("gmail", "search", "Search emails by query.", GmailSearchArgs)(
            gmail.gmail_search
        )
        registry.freeze_registry()
        app = create_app(agent=_agent(llm), config=_config())  # type: ignore[arg-type]
        client = TestClient(app, client=(_IP, 50000), follow_redirects=False)

        org_id = _create_org(db, client, secrets)
        admin_session = _accept_invitation(db, client, secrets)
        _invite_colleague(db, client, admin_session, secrets)
        member_session = _log_in(client, secrets)
        _request_resets(db, client, org_id, secrets)
        _deliver_outbox(db, monkeypatch)
        chat_turns = _chat(db, client, member_session, llm, gmail_requests)
        _connect_google(db, client)
        crashed = _crash(app, member_session)
        _health(client)
        output = sink.getvalue()
    return _Run(
        output=output,
        chat_turns=chat_turns,
        crashed=crashed,
        secrets=secrets,
        login_delays=tuple(login_delays),
    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _forms(text: str) -> set[str]:
    """The text as a log line could carry it: raw, URL-encoded, JSON-, ascii- and
    bytes-repr-escaped."""
    return {
        text,
        quote(text, safe=""),
        quote_plus(text),
        json.dumps(text)[1:-1],
        ascii(text)[1:-1],
        repr(text.encode())[2:-1],
    }


def _needles(run: _Run) -> dict[str, str]:
    """Every string that must not appear (casefolded) -> what it is."""
    needles: dict[str, str] = {}
    for content in _CONTENT:
        for piece in (content.value, *content.fragments):
            for form in _forms(piece):
                needles.setdefault(form.casefold(), content.label)
    for secret, label in run.secrets.items():
        for piece in (secret, secret[:16], secret[-16:]):
            needles.setdefault(piece.casefold(), label)
        needles.setdefault(hashlib.sha256(secret.encode()).hexdigest(), f"{label} (sha256)")
    assert all(len(needle) >= 8 for needle in needles), "a needle is too short to be distinctive"
    return needles


def _leaks(texts: Iterable[str], needles: dict[str, str]) -> list[str]:
    """One entry per (text, needle) match, case-insensitive."""
    found: list[str] = []
    for text in texts:
        folded = text.casefold()
        found.extend(
            f"{label} ({needle!r}) in {text!r}"
            for needle, label in needles.items()
            if needle in folded
        )
    return found


def _report(leaks: list[str]) -> str:
    return f"{len(leaks)} leak(s):\n" + "\n".join(leaks[:40])


def _json_records(run: _Run) -> list[dict[str, Any]]:
    """Every line of a JSON-format sink, parsed; each must be one JSON object."""
    records: list[dict[str, Any]] = []
    for number, line in enumerate(run.lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            pytest.fail(f"line {number} is not JSON: {line!r}")
        assert isinstance(record, dict), f"line {number} is not a JSON object: {line!r}"
        records.append(record)
    return records


def _strings(value: object) -> Iterator[str]:
    """Every string in a decoded JSON value: keys and values, at any depth."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _assert_captured(run: _Run) -> None:
    """The sink isn't empty and holds every content-free line the scenario produces."""
    assert run.output.strip(), "the configured handler wrote nothing"
    missing = [
        what
        for what, parts in _MARKERS.items()
        if not any(all(part in line for part in parts) for line in run.lines)
    ]
    assert not missing, f"expected log lines are missing: {missing}"


def _request_id(response: httpx.Response) -> str:
    """The response's X-Request-ID: 32 hex characters."""
    request_id = response.headers.get("x-request-id")
    assert request_id is not None, "no X-Request-ID header"
    assert _REQUEST_ID_RE.fullmatch(request_id), request_id
    return request_id


# ---------------------------------------------------------------------------
# 1. The capture is real (guards every other test against a vacuous pass)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_sink_holds_the_content_free_lines_of_every_step(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """A DEBUG record, both chat turns, the outbox failure and the unhandled exception
    reach the configured handler's stream."""
    run = scan(log_format)

    _assert_captured(run)


# ---------------------------------------------------------------------------
# 2. No content in the sink
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_no_fixture_string_reaches_the_log_sink(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """No title, file name, email, name, org name, message text, instructions,
    password, token or exception text: not raw, not encoded, not in part."""
    run = scan(log_format)

    _assert_captured(run)
    leaks = _leaks(run.lines, _needles(run))
    assert not leaks, _report(leaks)


def test_log_scan_json_every_line_is_an_object_with_the_contract_keys(
    scan: Callable[[str], _Run],
) -> None:
    """Every line of the JSON sink parses to an object with ts, level, logger, message
    and request_id."""
    run = scan("json")

    _assert_captured(run)
    records = _json_records(run)
    missing = [
        (number, sorted(_JSON_KEYS - record.keys()))
        for number, record in enumerate(records, start=1)
        if not record.keys() >= _JSON_KEYS
    ]
    assert not missing, missing


def test_log_scan_json_decoded_values_carry_no_fixture_string(
    scan: Callable[[str], _Run],
) -> None:
    """The decoded keys and values of every JSON record carry no content either."""
    run = scan("json")

    _assert_captured(run)
    values = [text for record in _json_records(run) for text in _strings(record)]
    leaks = _leaks(values, _needles(run))
    assert not leaks, _report(leaks)


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_no_url_is_logged_with_its_query_string(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """The Gmail search (``?q=``) and the OAuth callback (``?code=&state=``) URLs never
    reach the sink with their query strings."""
    run = scan(log_format)

    _assert_captured(run)
    with_query = [line for line in run.lines if _URL_WITH_QUERY_RE.search(line)]
    assert not with_query, with_query


# ---------------------------------------------------------------------------
# 3. Unhandled exceptions: by type and request ID only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_unhandled_exception_answers_500_with_a_request_id(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """The escaping RuntimeError is a generic JSON 500 carrying an X-Request-ID."""
    run = scan(log_format)

    assert run.crashed.status_code == 500
    assert run.crashed.json() == {"detail": "Internal error"}
    _request_id(run.crashed)


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_unhandled_exception_is_logged_by_type_and_request_id(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """The log line names the class and the 500's request ID; no message text, no
    traceback."""
    run = scan(log_format)

    request_id = _request_id(run.crashed)
    lines = [line for line in run.lines if _UNHANDLED in line]
    assert lines, "the unhandled exception wasn't logged"
    assert all(request_id in line for line in lines), (request_id, lines)
    assert "Traceback" not in run.output
    assert not _leaks(lines, _needles(run)), lines
    if log_format == "json":
        records = [json.loads(line) for line in lines]
        assert all(record["message"] == _UNHANDLED for record in records), records
        assert all(record["request_id"] == request_id for record in records), records


# ---------------------------------------------------------------------------
# 4. Per-request ID on the lines of a request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_format", _FORMATS)
def test_log_scan_chat_lines_carry_their_requests_id(
    scan: Callable[[str], _Run], log_format: str
) -> None:
    """Each chat turn's "Processing message" line carries that turn's X-Request-ID."""
    run = scan(log_format)

    expected = [_request_id(turn) for turn in run.chat_turns]
    assert len(set(expected)) == 2, "two requests got the same request ID"
    lines = [line for line in run.lines if "Processing message for session" in line]
    assert len(lines) == 2, lines
    if log_format == "json":
        assert [json.loads(line)["request_id"] for line in lines] == expected
    else:
        assert all(rid in line for rid, line in zip(expected, lines, strict=True)), lines
