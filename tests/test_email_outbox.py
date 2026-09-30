"""Tests for admino.email_outbox — the transactional email outbox and its sender (GH-148).

Request handlers never talk to SMTP. They call enqueue_email(), which writes one
email_outbox row (migration 0006, tests/test_migration_0006.py) with one
parameterized INSERT ... SELECT from users: the recipient address and the
language come from the users row (users.email, users.ui_language), never from
the caller. A background task, run_outbox_sender(), started by the server
lifespan when SMTP is configured, delivers due rows with retries and backoff.

What these tests pin down:
- The constants (10 attempts, 60 s base backoff doubling up to 6 h, a 10 minute
  send lease, batches of 10, a 10 s poll, a daily purge, 30 days of retention)
  and backoff_seconds().
- enqueue_email() issues exactly one INSERT ... SELECT ... FROM users WHERE
  id = $1 AND deleted_at IS NULL ... RETURNING id, binds (user_id, template
  key, params JSON), raises RecipientNotFoundError for an unknown or deleted
  user, refuses non-TemplateParams, and never touches SMTP: it succeeds while
  SMTP is down (so an SMTP failure never breaks the request).
- deliver_due() runs one sender pass: it fails rows that exhausted their
  attempts, claims a batch (FOR UPDATE SKIP LOCKED, attempts + 1, a lease),
  renders and delivers each row, then marks it sent (params scrubbed), backs
  it off (params kept), or fails it for good (params scrubbed). Rows that can
  never be sent (bad params, unknown template, render/build errors) fail at
  once. One bad row never stops the batch.
- purge_finished() deletes sent/failed rows older than the retention.
- run_outbox_sender() loops deliver_due / sleep, purges on the first pass and
  then daily, survives failures and stops on cancellation.
- The server lifespan starts the sender only when load_smtp_config() returns
  a config, and cancels it before closing the pool.

All asyncpg calls, smtplib and the mailer's deliver() are mocked. No real
PostgreSQL, network or SMTP connections are made.

Security notes:
- No content in logs (tracker #139 §5): outbox IDs, template keys, attempt
  counts and exception class names only; never an address, a link, an org
  name, SMTP credentials or an exception's text (SMTP errors echo addresses).
  The log scan test exercises every path at DEBUG.
- One-time links don't outlive delivery: params are cleared ('{}') when a row
  reaches sent or its final failed; retries keep them.
- Parameterized SQL only: no value is ever part of the SQL text.
- email_outbox.py imports only the stdlib, asyncpg, pydantic and admino's
  template and mailer modules; permissions.py gains no import.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import json
import logging
import re
import smtplib
import ssl
import sys
import threading
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import asyncpg
import pytest

import admino.email_outbox as outbox_mod
from admino.access import SealedModel
from admino.email_outbox import (
    BACKOFF_BASE_SECONDS,
    BACKOFF_MAX_SECONDS,
    BATCH_SIZE,
    FINISHED_RETENTION_DAYS,
    MAX_ATTEMPTS,
    POLL_INTERVAL_SECONDS,
    PURGE_INTERVAL_SECONDS,
    SEND_LEASE_SECONDS,
    OutboxStatus,
    RecipientNotFoundError,
    backoff_seconds,
    deliver_due,
    enqueue_email,
    purge_finished,
    run_outbox_sender,
)
from admino.email_templates import (
    AccountDeactivatedParams,
    BudgetAlertParams,
    InvitationParams,
    PasswordResetParams,
    TemplateParams,
    render,
)
from admino.mailer import SmtpConfig, load_smtp_config
from admino.server import _lifespan, create_app
from tests.lifespan_stubs import (
    patch_login_throttle_purge_job,
    patch_org_purge_job,
    patch_tools_gate,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USER = UUID("6d1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b")
_OUTBOX_ID = UUID("0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d")
_ROW_A = UUID("a1a1a1a1-b2b2-4c3c-8d4d-e5e5e5e5e5e5")
_ROW_B = UUID("b2b2b2b2-c3c3-4d4d-9e5e-f6f6f6f6f6f6")
_ROW_C = UUID("c3c3c3c3-d4d4-4e5e-af6f-a7a7a7a7a7a7")

_ALICE = "alice-3f9e@example.invalid"
_BOB = "bob-8a1c@example.invalid"
_CAROL = "carol-2d7b@example.invalid"
_ORG_NAME = "Geheim-Marker Treuhand AG"
_ACCEPT_LINK = "https://admino.example.ch/invite/inv-tok-SECRET-51c3"
_RESET_LINK = "https://admino.example.ch/reset/rst-tok-SECRET-0b7d"
_EXPIRES_AT = datetime(2026, 9, 1, 14, 30, tzinfo=UTC)

_SMTP_HOST = "smtp.admino.invalid"
_SMTP_USER = "smtp-user-e41f@admino.invalid"
_SMTP_PASSWORD = "pw-outbox-S3cret-marker"
_SMTP_FROM = "noreply-c2a9@admino.invalid"

_SRC_DIR = Path(outbox_mod.__file__).resolve().parent

# The real asyncio.sleep, kept before any test patches the module attribute.
_REAL_SLEEP = asyncio.sleep

# Formatting-tolerant SQL fragments (normalized SQL is lowercase, single-spaced).
_NOW = (
    r"(?:now\s*\(\s*\)|current_timestamp|clock_timestamp\s*\(\s*\)"
    r"|statement_timestamp\s*\(\s*\)|transaction_timestamp\s*\(\s*\))"
)
_CAST = r"(?:\s*::\s*\w+(?:\s+precision)?)?"
_SCRUB = r"\bparams\s*=\s*'\{\}'(?:\s*::\s*jsonb)?"
_FINISHED_NOW = rf"\bfinished_at\s*=\s*{_NOW}"
_BACKOFF_SET = (
    rf"\bnext_attempt_at\s*=\s*{_NOW}\s*\+\s*make_interval\s*\(\s*secs\s*=>\s*\$2{_CAST}\s*\)"
)


# ---------------------------------------------------------------------------
# Helpers: params, config, rows
# ---------------------------------------------------------------------------


class _NotTemplateParams(SealedModel):
    """A sealed model that is not one of the email templates."""

    org_name: str


def _config(**overrides: Any) -> SmtpConfig:
    """A valid platform SMTP config."""
    kwargs: dict[str, Any] = {
        "host": _SMTP_HOST,
        "port": 587,
        "username": _SMTP_USER,
        "password": _SMTP_PASSWORD,
        "from_address": _SMTP_FROM,
    }
    kwargs.update(overrides)
    return SmtpConfig(**kwargs)


def _invitation(**overrides: Any) -> InvitationParams:
    """Sample invitation params."""
    kwargs: dict[str, Any] = {
        "org_name": _ORG_NAME,
        "accept_link": _ACCEPT_LINK,
        "expires_at": _EXPIRES_AT,
    }
    kwargs.update(overrides)
    return InvitationParams(**kwargs)


def _reset() -> PasswordResetParams:
    """Sample password reset params."""
    return PasswordResetParams(reset_link=_RESET_LINK, expires_at=_EXPIRES_AT)


def _row(
    *,
    row_id: UUID = _ROW_A,
    address: str = _ALICE,
    params: TemplateParams | None = None,
    template_key: str | None = None,
    language: str = "en",
    attempts: int = 1,
    stored: Any = None,
    as_text: bool = True,
) -> dict[str, Any]:
    """A claimed email_outbox row, as the claim's RETURNING gives it.

    ``params`` comes back as JSON text (asyncpg's default jsonb codec) unless
    ``as_text`` is False; ``stored`` replaces the stored params data verbatim.
    """
    params = params if params is not None else _invitation()
    data = stored if stored is not None else params.model_dump(mode="json")
    return {
        "id": row_id,
        "recipient_address": address,
        "template_key": template_key if template_key is not None else params.template.value,
        "language": language,
        "params": json.dumps(data) if as_text and not isinstance(data, str) else data,
        "attempts": attempts,
    }


def _normalized(sql: str) -> str:
    """Collapse whitespace, drop a trailing semicolon and lowercase."""
    return re.sub(r"\s+", " ", sql).strip().rstrip(";").strip().lower()


class _Statement(NamedTuple):
    """One statement the fake pool received."""

    method: str
    sql: str
    args: tuple[Any, ...]


class _FakePool:
    """A mocked asyncpg pool that records every statement in order.

    The first fetch() (the claim) returns ``rows``; later ones return nothing.
    execute() answers with an asyncpg status string.
    """

    def __init__(
        self, rows: list[dict[str, Any]] | None = None, *, status: str = "UPDATE 1"
    ) -> None:
        self.statements: list[_Statement] = []
        self._rows = list(rows or [])
        self._claimed = False
        self._status = status
        self.execute = AsyncMock(side_effect=self._execute)
        self.fetch = AsyncMock(side_effect=self._fetch)
        self.fetchrow = AsyncMock(return_value=None)
        self.fetchval = AsyncMock(return_value=None)

    async def _execute(self, sql: str, *args: Any) -> str:
        self.statements.append(_Statement("execute", _normalized(sql), args))
        return self._status

    async def _fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.statements.append(_Statement("fetch", _normalized(sql), args))
        if self._claimed:
            return []
        self._claimed = True
        return self._rows


def _sweeps(pool: _FakePool) -> list[_Statement]:
    """The exhaust sweeps: executes that fail pending rows with attempts >= $1."""
    return [
        s
        for s in pool.statements
        if s.method == "execute" and re.search(r"\battempts\s*>=\s*\$1\b", s.sql)
    ]


def _claims(pool: _FakePool) -> list[_Statement]:
    """The claim statements (fetch)."""
    return [s for s in pool.statements if s.method == "fetch"]


def _row_updates(pool: _FakePool, row_id: UUID) -> list[_Statement]:
    """The executes bound to one row (its id is $1)."""
    return [s for s in pool.statements if s.method == "execute" and s.args[:1] == (row_id,)]


def _kind(sql: str) -> str:
    """Classify a per-row UPDATE by its content: sent, failed or retry."""
    if re.search(r"\bstatus\s*=\s*'sent'", sql):
        return "sent"
    if re.search(r"\bstatus\s*=\s*'failed'", sql):
        return "failed"
    if "make_interval" in sql:
        return "retry"
    return "other"


def _only_update(pool: _FakePool, row_id: UUID) -> _Statement:
    """The single UPDATE a row received in the pass."""
    updates = _row_updates(pool, row_id)
    assert len(updates) == 1, updates
    return updates[0]


def _split_update(sql: str) -> tuple[str, str]:
    """Return (SET clause, WHERE clause) of an UPDATE email_outbox statement."""
    match = re.fullmatch(r"update\s+email_outbox\s+set\s+(.*?)\s+where\s+(.*)", sql)
    assert match is not None, f"not an UPDATE email_outbox ... WHERE: {sql}"
    return match.group(1), match.group(2)


def _assert_row_guard(where: str) -> None:
    """The per-row UPDATE targets $1 and only while the row is still pending."""
    assert re.search(r"\bid\s*=\s*\$1\b", where), where
    assert re.search(r"\bstatus\s*=\s*'pending'", where), where


def _assert_terminal(sql: str, status: str) -> None:
    """A terminal UPDATE: status, params scrubbed, finished_at = now(), guarded by id and
    pending status."""
    set_clause, where = _split_update(sql)
    assert re.search(rf"\bstatus\s*=\s*'{status}'", set_clause), set_clause
    assert re.search(_SCRUB, set_clause), set_clause
    assert re.search(_FINISHED_NOW, set_clause), set_clause
    _assert_row_guard(where)


def _delivered(deliver: AsyncMock) -> list[Any]:
    """The messages deliver() was awaited with (positional or keyword)."""
    messages: list[Any] = []
    for call in deliver.await_args_list:
        messages.append(call.args[1] if len(call.args) > 1 else call.kwargs["message"])
    return messages


def _deliver_failing_for(*addresses: str, error: Exception | None = None) -> AsyncMock:
    """A fake mailer.deliver that raises for the given recipients and succeeds otherwise."""

    async def fake_deliver(config: SmtpConfig, message: Any) -> None:
        if str(message["To"]) in addresses:
            raise error or smtplib.SMTPServerDisconnected("Connection unexpectedly closed")

    return AsyncMock(side_effect=fake_deliver)


def _patch_deliver(mock: AsyncMock) -> Any:
    """Patch mailer.deliver as email_outbox looks it up (``from admino import mailer``)."""
    return patch("admino.email_outbox.mailer.deliver", mock)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """WARNING-or-higher records from admino's own loggers."""
    return [
        record
        for record in caplog.records
        if record.name.startswith("admino") and record.levelno >= logging.WARNING
    ]


def _assert_absent(caplog: pytest.LogCaptureFixture, *markers: str) -> None:
    """No marker appears in any record's message, args or the formatted log output."""
    for record in caplog.records:
        text = record.getMessage() + repr(record.args)
        for marker in markers:
            assert marker not in text, f"{marker!r} leaked into {text!r}"
    for marker in markers:
        assert marker not in caplog.text, f"{marker!r} leaked into the log output"


@pytest.fixture(autouse=True)
def _no_real_smtp() -> Iterator[None]:
    """Guard: no test in this file may open a real SMTP connection."""
    guard = MagicMock(side_effect=AssertionError("a real SMTP connection was attempted"))
    with patch("smtplib.SMTP", guard), patch("smtplib.SMTP_SSL", guard):
        yield


@pytest.fixture()
def conn() -> MagicMock:
    """A mocked asyncpg connection whose fetchval returns the new outbox id."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.execute = AsyncMock(return_value="INSERT 0 1")
    connection.fetch = AsyncMock(return_value=[])
    connection.fetchrow = AsyncMock(return_value=None)
    connection.fetchval = AsyncMock(return_value=_OUTBOX_ID)
    return connection


# ---------------------------------------------------------------------------
# 1. Constants, status enum, error type
# ---------------------------------------------------------------------------


class TestConstants:
    """The retry, lease, batch, poll and retention constants."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param(lambda: MAX_ATTEMPTS, 10, id="max-attempts"),
            pytest.param(lambda: BACKOFF_BASE_SECONDS, 60, id="backoff-base"),
            pytest.param(lambda: BACKOFF_MAX_SECONDS, 21600, id="backoff-max"),
            pytest.param(lambda: SEND_LEASE_SECONDS, 600, id="send-lease"),
            pytest.param(lambda: BATCH_SIZE, 10, id="batch-size"),
            pytest.param(lambda: POLL_INTERVAL_SECONDS, 10, id="poll-interval"),
            pytest.param(lambda: PURGE_INTERVAL_SECONDS, 86400, id="purge-interval"),
            pytest.param(lambda: FINISHED_RETENTION_DAYS, 30, id="retention-days"),
        ],
    )
    def test_email_outbox_constant_values(self, value: Callable[[], int], expected: int) -> None:
        """Each constant has the value the issue fixes."""
        assert value() == expected

    def test_email_outbox_lease_outlasts_the_smtp_timeout(self) -> None:
        """A claimed row's lease (600 s) is longer than one SMTP attempt can take, so a slow
        send isn't claimed twice."""
        from admino.mailer import SMTP_TIMEOUT_SECONDS

        assert SEND_LEASE_SECONDS > SMTP_TIMEOUT_SECONDS * 4

    def test_email_outbox_status_is_a_str_enum(self) -> None:
        """OutboxStatus is a StrEnum with exactly pending, sent and failed."""
        assert issubclass(OutboxStatus, StrEnum)
        assert {status.value for status in OutboxStatus} == {"pending", "sent", "failed"}
        assert OutboxStatus.PENDING == "pending"
        assert OutboxStatus.SENT == "sent"
        assert OutboxStatus.FAILED == "failed"

    def test_email_outbox_recipient_not_found_is_an_exception(self) -> None:
        """RecipientNotFoundError is an Exception subclass."""
        assert issubclass(RecipientNotFoundError, Exception)


class TestBackoff:
    """backoff_seconds(attempts) = min(60 * 2 ** (attempts - 1), 21600)."""

    @pytest.mark.parametrize(
        ("attempts", "expected"),
        [
            (1, 60),
            (2, 120),
            (3, 240),
            (4, 480),
            (8, 7680),
            (9, 15360),
            (10, 21600),
            (20, 21600),
            (1000, 21600),
        ],
    )
    def test_email_outbox_backoff_values(self, attempts: int, expected: int) -> None:
        """Doubling from 60 s, capped at 6 hours."""
        assert backoff_seconds(attempts) == expected

    def test_email_outbox_backoff_returns_int(self) -> None:
        """An int number of seconds (it binds as make_interval(secs => $2))."""
        assert type(backoff_seconds(3)) is int

    def test_email_outbox_backoff_is_non_decreasing(self) -> None:
        """Each retry waits at least as long as the one before."""
        values = [backoff_seconds(n) for n in range(1, 40)]

        assert values == sorted(values)
        assert max(values) == BACKOFF_MAX_SECONDS

    @pytest.mark.parametrize("attempts", [0, -1, -100])
    def test_email_outbox_backoff_refuses_attempts_below_one(self, attempts: int) -> None:
        """There is no backoff before the first attempt."""
        with pytest.raises(ValueError, match=r".*"):
            backoff_seconds(attempts)


# ---------------------------------------------------------------------------
# 2. enqueue_email(): one parameterized INSERT ... SELECT FROM users
# ---------------------------------------------------------------------------

_ENQUEUE_RE = re.compile(
    r"^insert\s+into\s+email_outbox\s*\(([^)]*)\)\s*select\s+(.*?)\s+from\s+users\b(.*)$"
)


def _strip_qualifier(item: str) -> str:
    """Drop a table qualifier (u.email) and a trailing AS alias from a SELECT item."""
    item = re.sub(r"\s+as\s+\w+$", "", item.strip())
    return re.sub(r"^\w+\.", "", item)


def _enqueue_statement(executor: MagicMock) -> tuple[str, dict[str, str], str, tuple[Any, ...]]:
    """Return (SQL, INSERT column -> SELECT item, text after FROM users, bind args)."""
    assert executor.fetchval.await_count == 1, "enqueue_email must issue exactly one fetchval"
    call = executor.fetchval.await_args
    assert call is not None
    sql = _normalized(call.args[0])
    match = _ENQUEUE_RE.match(sql)
    assert match is not None, ("enqueue_email must INSERT ... SELECT from users", sql)
    columns = [column.strip().strip('"') for column in match.group(1).split(",")]
    items = [item.strip() for item in match.group(2).split(",")]
    assert len(columns) == len(items), (columns, items)
    return sql, dict(zip(columns, items, strict=True)), match.group(3), tuple(call.args[1:])


class TestEnqueue:
    """enqueue_email() queues one row; the users table supplies address and language."""

    async def test_email_outbox_enqueue_returns_the_outbox_id(self, conn: MagicMock) -> None:
        """The id RETURNING gives back."""
        assert await enqueue_email(conn, user_id=_USER, params=_invitation()) == _OUTBOX_ID

    async def test_email_outbox_enqueue_issues_one_fetchval_only(self, conn: MagicMock) -> None:
        """Exactly one statement, through fetchval: no execute, fetch or fetchrow."""
        await enqueue_email(conn, user_id=_USER, params=_invitation())

        assert conn.fetchval.await_count == 1
        conn.execute.assert_not_awaited()
        conn.fetch.assert_not_awaited()
        conn.fetchrow.assert_not_awaited()

    async def test_email_outbox_enqueue_works_with_a_pool(self, mock_pool: MagicMock) -> None:
        """A pool works as the executor too (anything with fetchval)."""
        mock_pool.fetchval = AsyncMock(return_value=_OUTBOX_ID)

        assert await enqueue_email(mock_pool, user_id=_USER, params=_invitation()) == _OUTBOX_ID
        assert mock_pool.fetchval.await_count == 1

    async def test_email_outbox_enqueue_binds_user_template_and_params(
        self, conn: MagicMock
    ) -> None:
        """$1 is the user UUID, $2 the template key, $3 the params as a JSON string."""
        params = _invitation()

        await enqueue_email(conn, user_id=_USER, params=params)

        _, _, _, args = _enqueue_statement(conn)
        assert len(args) == 3
        assert args[0] == _USER
        assert isinstance(args[0], UUID)
        assert args[1] == "invitation"
        assert isinstance(args[2], str)
        assert json.loads(args[2]) == params.model_dump(mode="json")

    async def test_email_outbox_enqueue_selects_from_live_users(self, conn: MagicMock) -> None:
        """... FROM users WHERE id = $1 AND deleted_at IS NULL ... RETURNING id."""
        await enqueue_email(conn, user_id=_USER, params=_invitation())

        _, _, tail, _ = _enqueue_statement(conn)
        assert re.search(r"\bwhere\b", tail), tail
        assert re.search(r"(?:\w+\.)?\bid\s*=\s*\$1\b", tail), tail
        assert re.search(r"(?:\w+\.)?\bdeleted_at\s+is\s+null\b", tail), tail
        assert re.search(r"\breturning\s+(?:\w+\.)?id$", tail), tail

    async def test_email_outbox_enqueue_takes_address_and_language_from_users(
        self, conn: MagicMock
    ) -> None:
        """recipient_address comes from users.email and language from users.ui_language;
        the template key and params are the bound $2 and $3."""
        await enqueue_email(conn, user_id=_USER, params=_invitation())

        _, mapping, _, _ = _enqueue_statement(conn)
        assert _strip_qualifier(mapping["recipient_address"]) == "email"
        assert _strip_qualifier(mapping["language"]) == "ui_language"
        assert _strip_qualifier(mapping["recipient_user_id"]) in {"id", "$1", "$1::uuid"}
        assert re.fullmatch(r"\$2(?:::text)?", mapping["template_key"]), mapping
        assert re.fullmatch(r"\$3(?:::jsonb)?", mapping["params"]), mapping

    def test_email_outbox_enqueue_has_no_language_parameter(self) -> None:
        """enqueue_email(executor, *, user_id, params): the caller can't pick the language."""
        parameters = inspect.signature(enqueue_email).parameters

        assert list(parameters) == ["executor", "user_id", "params"]
        assert parameters["user_id"].kind is inspect.Parameter.KEYWORD_ONLY
        assert parameters["params"].kind is inspect.Parameter.KEYWORD_ONLY

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param(_invitation, id="invitation"),
            pytest.param(_reset, id="password-reset"),
            pytest.param(lambda: AccountDeactivatedParams(org_name=_ORG_NAME), id="deactivated"),
            pytest.param(
                lambda: BudgetAlertParams(
                    org_name=_ORG_NAME,
                    month=date(2026, 9, 1),
                    usage_link="https://admino.example.ch/admin/usage",
                ),
                id="budget-alert",
            ),
        ],
    )
    async def test_email_outbox_enqueue_binds_each_template_key(
        self, conn: MagicMock, params: Callable[[], TemplateParams]
    ) -> None:
        """The key bound as $2 is the params' own template key."""
        built = params()

        await enqueue_email(conn, user_id=_USER, params=built)

        _, _, _, args = _enqueue_statement(conn)
        assert args[1] == built.template.value
        assert json.loads(args[2]) == built.model_dump(mode="json")

    async def test_email_outbox_enqueue_puts_no_value_in_the_sql(self, conn: MagicMock) -> None:
        """The org name, the link and the user id travel as bind parameters only."""
        await enqueue_email(conn, user_id=_USER, params=_invitation())

        call = conn.fetchval.await_args
        assert call is not None
        sql = call.args[0]
        for value in (_ORG_NAME, _ACCEPT_LINK, "inv-tok-SECRET", str(_USER), _USER.hex):
            assert value not in sql
        assert "'invitation'" not in sql.lower()

    async def test_email_outbox_enqueue_unknown_user_raises(self, conn: MagicMock) -> None:
        """No live users row (unknown or soft-deleted): RecipientNotFoundError."""
        conn.fetchval = AsyncMock(return_value=None)

        with pytest.raises(RecipientNotFoundError):
            await enqueue_email(conn, user_id=_USER, params=_invitation())

    async def test_email_outbox_recipient_error_carries_no_ids(self, conn: MagicMock) -> None:
        """The error names no user id, address or params value."""
        conn.fetchval = AsyncMock(return_value=None)

        with pytest.raises(RecipientNotFoundError) as excinfo:
            await enqueue_email(conn, user_id=_USER, params=_invitation())

        text = f"{excinfo.value!s} {excinfo.value!r}"
        for value in (str(_USER), _USER.hex, _ORG_NAME, _ACCEPT_LINK):
            assert value not in text

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param(
                {"org_name": _ORG_NAME, "accept_link": _ACCEPT_LINK, "expires_at": "x"},
                id="dict",
            ),
            pytest.param(None, id="none"),
            pytest.param("invitation", id="template-key-string"),
            pytest.param(_NotTemplateParams(org_name=_ORG_NAME), id="other-sealed-model"),
        ],
    )
    async def test_email_outbox_enqueue_refuses_non_template_params(
        self, conn: MagicMock, params: Any
    ) -> None:
        """Anything but a TemplateParams instance is a TypeError, before any DB call."""
        with pytest.raises(TypeError):
            await enqueue_email(conn, user_id=_USER, params=params)

        conn.fetchval.assert_not_awaited()

    async def test_email_outbox_enqueue_succeeds_while_smtp_is_down(self, conn: MagicMock) -> None:
        """SMTP failure doesn't break the request: with every mailer and smtplib entry point
        failing, enqueue still returns an id and never calls any of them."""
        down = smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
        deliver = AsyncMock(side_effect=down)
        send = MagicMock(side_effect=down)
        build = MagicMock(side_effect=down)
        smtp = MagicMock(side_effect=ConnectionRefusedError("refused"))

        with (
            patch("admino.mailer.deliver", deliver),
            patch("admino.mailer.send_message", send),
            patch("admino.mailer.build_message", build),
            patch("smtplib.SMTP", smtp),
            patch("smtplib.SMTP_SSL", smtp),
        ):
            result = await enqueue_email(conn, user_id=_USER, params=_invitation())

        assert result == _OUTBOX_ID
        deliver.assert_not_awaited()
        send.assert_not_called()
        build.assert_not_called()
        smtp.assert_not_called()

    async def test_email_outbox_enqueue_logs_no_content(
        self, conn: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """At most the outbox id and template key are logged: no org name or link."""
        caplog.set_level(logging.DEBUG)

        await enqueue_email(conn, user_id=_USER, params=_invitation())

        _assert_absent(caplog, _ORG_NAME, _ACCEPT_LINK, "inv-tok-SECRET")


# ---------------------------------------------------------------------------
# 3. deliver_due(): one sender pass
# ---------------------------------------------------------------------------


class TestDeliverDueSweepAndClaim:
    """The pass first fails exhausted rows, then claims a batch."""

    def test_email_outbox_deliver_due_signature_is_pool_and_config(self) -> None:
        """deliver_due(pool, config): one platform-wide SMTP account, no per-org config."""
        assert list(inspect.signature(deliver_due).parameters) == ["pool", "config"]

    async def test_email_outbox_deliver_due_sweeps_exhausted_rows_first(self) -> None:
        """The first statement fails pending rows with attempts >= MAX_ATTEMPTS whose lease has
        run out (a crashed last attempt), scrubbing their params."""
        pool = _FakePool([])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        first = pool.statements[0]
        assert first.method == "execute"
        assert first.args == (MAX_ATTEMPTS,)
        set_clause, where = _split_update(first.sql)
        assert re.search(r"\bstatus\s*=\s*'failed'", set_clause), set_clause
        assert re.search(_SCRUB, set_clause), set_clause
        assert re.search(_FINISHED_NOW, set_clause), set_clause
        assert re.search(r"\bstatus\s*=\s*'pending'", where), where
        assert re.search(r"\battempts\s*>=\s*\$1\b", where), where
        assert re.search(rf"\bnext_attempt_at\s*<=\s*{_NOW}", where), where

    async def test_email_outbox_deliver_due_sweep_precedes_claim(self) -> None:
        """Sweep, then claim."""
        pool = _FakePool([_row()])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        sweeps = _sweeps(pool)
        claims = _claims(pool)
        assert len(sweeps) == 1
        assert len(claims) == 1
        assert pool.statements.index(sweeps[0]) < pool.statements.index(claims[0])

    async def test_email_outbox_deliver_due_claims_one_batch(self) -> None:
        """One claim per pass, bound (BATCH_SIZE, SEND_LEASE_SECONDS, MAX_ATTEMPTS)."""
        pool = _FakePool([_row()])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        claims = _claims(pool)
        assert len(claims) == 1
        assert claims[0].args == (BATCH_SIZE, SEND_LEASE_SECONDS, MAX_ATTEMPTS)

    @pytest.mark.parametrize(
        "pattern",
        [
            pytest.param(r"\bupdate\s+email_outbox\s+set\b", id="update"),
            pytest.param(r"\battempts\s*=\s*attempts\s*\+\s*1\b", id="counts-the-attempt"),
            pytest.param(_BACKOFF_SET, id="takes-a-lease"),
            pytest.param(r"\bstatus\s*=\s*'pending'", id="pending-only"),
            pytest.param(rf"\bnext_attempt_at\s*<=\s*{_NOW}", id="due-only"),
            pytest.param(r"\battempts\s*<\s*\$3\b", id="attempts-left-only"),
            pytest.param(r"\border\s+by\s+(?:\w+\.)?next_attempt_at\b", id="oldest-first"),
            pytest.param(r"\blimit\s+\$1\b", id="batch-limit"),
            pytest.param(r"\bfor\s+update\s+skip\s+locked\b", id="skip-locked"),
        ],
    )
    async def test_email_outbox_deliver_due_claim_sql(self, pattern: str) -> None:
        """The claim takes due pending rows with attempts left, oldest first, FOR UPDATE SKIP
        LOCKED, counts the attempt and sets a lease: two senders never send one row twice."""
        pool = _FakePool([_row()])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        sql = _claims(pool)[0].sql
        assert re.search(pattern, sql), sql

    async def test_email_outbox_deliver_due_claim_returns_the_row_fields(self) -> None:
        """RETURNING id, recipient_address, template_key, language, params, attempts."""
        pool = _FakePool([_row()])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        match = re.search(r"\breturning\s+(.*)$", _claims(pool)[0].sql)
        assert match is not None
        returned = {re.sub(r"^\w+\.", "", item.strip()) for item in match.group(1).split(",")}
        assert {
            "id",
            "recipient_address",
            "template_key",
            "language",
            "params",
            "attempts",
        } <= returned

    async def test_email_outbox_deliver_due_puts_no_value_in_the_sql(self) -> None:
        """No row id, address, link or org name ever appears in a statement's SQL text."""
        pool = _FakePool([_row(), _row(row_id=_ROW_B, address=_BOB, attempts=MAX_ATTEMPTS)])

        with _patch_deliver(_deliver_failing_for(_BOB)):
            await deliver_due(pool, _config())

        for statement in pool.statements:
            for value in (str(_ROW_A), str(_ROW_B), _ALICE, _BOB, _ACCEPT_LINK, _ORG_NAME):
                assert value.lower() not in statement.sql

    async def test_email_outbox_deliver_due_nothing_due_returns_zero(self) -> None:
        """No claimed rows: 0 sent, nothing delivered, no row updates."""
        pool = _FakePool([])
        deliver = AsyncMock()

        with _patch_deliver(deliver):
            sent = await deliver_due(pool, _config())

        assert sent == 0
        deliver.assert_not_awaited()
        assert [s for s in pool.statements if s.method == "execute"] == _sweeps(pool)


class TestDeliverDueSuccess:
    """A delivered row is marked sent and its params are scrubbed."""

    async def test_email_outbox_deliver_due_delivers_to_the_row_address(self) -> None:
        """mailer.deliver(config, message) with a message to the row's stored address."""
        config = _config()
        pool = _FakePool([_row(address=_ALICE)])
        deliver = AsyncMock()

        with _patch_deliver(deliver):
            await deliver_due(pool, config)

        deliver.assert_awaited_once()
        call = deliver.await_args
        assert call is not None
        assert (call.args[0] if call.args else call.kwargs["config"]) is config
        (message,) = _delivered(deliver)
        assert str(message["To"]) == _ALICE

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    async def test_email_outbox_deliver_due_renders_in_the_row_language(
        self, language: str
    ) -> None:
        """The stored language (the recipient's ui_language at enqueue) picks the rendering."""
        params = _invitation()
        pool = _FakePool([_row(params=params, language=language)])
        deliver = AsyncMock()

        with _patch_deliver(deliver):
            await deliver_due(pool, _config())

        (message,) = _delivered(deliver)
        assert str(message["Subject"]) == render(params, language).subject

    async def test_email_outbox_deliver_due_builds_with_the_rendered_template(self) -> None:
        """mailer.build_message(config, to=address, rendered=render(params, language))."""
        from admino import mailer

        params = _reset()
        config = _config()
        pool = _FakePool([_row(params=params, language="fr", address=_CAROL)])
        build = MagicMock(wraps=mailer.build_message)

        with _patch_deliver(AsyncMock()), patch("admino.email_outbox.mailer.build_message", build):
            await deliver_due(pool, config)

        build.assert_called_once()
        call = build.call_args
        assert (call.args[0] if call.args else call.kwargs["config"]) is config
        assert call.kwargs["to"] == _CAROL
        assert call.kwargs["rendered"] == render(params, "fr")

    @pytest.mark.parametrize("as_text", [True, False], ids=["json-text", "decoded-dict"])
    async def test_email_outbox_deliver_due_reads_params_as_text_or_dict(
        self, as_text: bool
    ) -> None:
        """The params column may arrive as JSON text or as a dict: both deliver."""
        pool = _FakePool([_row(as_text=as_text)])
        deliver = AsyncMock()

        with _patch_deliver(deliver):
            sent = await deliver_due(pool, _config())

        assert sent == 1
        deliver.assert_awaited_once()

    async def test_email_outbox_deliver_due_marks_sent_and_scrubs(self) -> None:
        """UPDATE ... SET status = 'sent', params = '{}', finished_at = now() WHERE id = $1
        AND status = 'pending', bound (row id,)."""
        pool = _FakePool([_row(row_id=_ROW_A)])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        update = _only_update(pool, _ROW_A)
        assert _kind(update.sql) == "sent"
        assert update.args == (_ROW_A,)
        _assert_terminal(update.sql, "sent")

    async def test_email_outbox_deliver_due_returns_the_sent_count(self) -> None:
        """The pass returns how many messages it sent."""
        rows = [
            _row(row_id=_ROW_A, address=_ALICE),
            _row(row_id=_ROW_B, address=_BOB),
            _row(row_id=_ROW_C, address=_CAROL),
        ]
        pool = _FakePool(rows)

        with _patch_deliver(_deliver_failing_for(_BOB)):
            sent = await deliver_due(pool, _config())

        assert sent == 2

    async def test_email_outbox_deliver_due_sends_off_the_event_loop(self) -> None:
        """The blocking SMTP send runs in a worker thread (mailer.deliver -> to_thread), so the
        sender never blocks request handling."""
        loop_thread = threading.get_ident()
        threads: list[int] = []

        def fake_send(config: SmtpConfig, message: Any) -> None:
            threads.append(threading.get_ident())

        pool = _FakePool([_row()])
        with patch("admino.mailer.send_message", fake_send):
            sent = await asyncio.wait_for(deliver_due(pool, _config()), timeout=5)

        assert sent == 1
        assert len(threads) == 1
        assert threads[0] != loop_thread


_DELIVERY_ERRORS: list[Any] = [
    pytest.param(
        lambda: smtplib.SMTPRecipientsRefused({_ALICE: (550, b"no such user " + _ALICE.encode())}),
        id="recipients-refused",
    ),
    pytest.param(lambda: smtplib.SMTPServerDisconnected("gone"), id="disconnected"),
    pytest.param(lambda: smtplib.SMTPAuthenticationError(535, b"denied"), id="auth"),
    pytest.param(lambda: smtplib.SMTPDataError(451, b"try again later"), id="data-error"),
    pytest.param(lambda: ConnectionRefusedError("refused"), id="connection-refused"),
    pytest.param(lambda: TimeoutError("timed out"), id="timeout"),
    pytest.param(lambda: ssl.SSLError("handshake failed"), id="tls"),
    pytest.param(lambda: RuntimeError("boom"), id="runtime-error"),
]


class TestDeliverDueRetry:
    """A failed delivery with attempts left is backed off; its params are kept."""

    @pytest.mark.parametrize("attempts", [1, 2, 3, 9])
    async def test_email_outbox_deliver_due_backs_off_by_attempt(self, attempts: int) -> None:
        """UPDATE ... SET next_attempt_at = now() + make_interval(secs => $2) WHERE id = $1 AND
        status = 'pending', bound (row id, backoff_seconds(attempts))."""
        pool = _FakePool([_row(row_id=_ROW_A, attempts=attempts)])

        with _patch_deliver(_deliver_failing_for(_ALICE)):
            await deliver_due(pool, _config())

        update = _only_update(pool, _ROW_A)
        assert _kind(update.sql) == "retry"
        assert update.args == (_ROW_A, backoff_seconds(attempts))
        set_clause, where = _split_update(update.sql)
        assert re.search(_BACKOFF_SET, set_clause), set_clause
        _assert_row_guard(where)

    async def test_email_outbox_deliver_due_retry_keeps_status_and_params(self) -> None:
        """A retry doesn't touch status or params (the link is still needed)."""
        pool = _FakePool([_row(row_id=_ROW_A, attempts=2)])

        with _patch_deliver(_deliver_failing_for(_ALICE)):
            await deliver_due(pool, _config())

        set_clause, _ = _split_update(_only_update(pool, _ROW_A).sql)
        assert re.search(r"\bstatus\s*=", set_clause) is None, set_clause
        assert re.search(r"\bparams\s*=", set_clause) is None, set_clause
        assert re.search(r"\bfinished_at\s*=", set_clause) is None, set_clause

    @pytest.mark.parametrize("make_error", _DELIVERY_ERRORS)
    async def test_email_outbox_deliver_due_retries_any_delivery_error(
        self, make_error: Callable[[], Exception]
    ) -> None:
        """Any exception from deliver() leads to a retry while attempts are left."""
        pool = _FakePool([_row(row_id=_ROW_A, attempts=1)])

        with _patch_deliver(AsyncMock(side_effect=make_error())):
            sent = await deliver_due(pool, _config())

        assert sent == 0
        assert _kind(_only_update(pool, _ROW_A).sql) == "retry"


class TestDeliverDueFinalFailure:
    """The last allowed attempt failing fails the row for good; params are scrubbed."""

    async def test_email_outbox_deliver_due_final_failure_marks_failed(self) -> None:
        """attempts == MAX_ATTEMPTS: UPDATE ... SET status = 'failed', params = '{}',
        finished_at = now() WHERE id = $1 AND status = 'pending', bound (row id,)."""
        pool = _FakePool([_row(row_id=_ROW_A, attempts=MAX_ATTEMPTS)])

        with _patch_deliver(_deliver_failing_for(_ALICE)):
            sent = await deliver_due(pool, _config())

        assert sent == 0
        update = _only_update(pool, _ROW_A)
        assert _kind(update.sql) == "failed"
        assert update.args == (_ROW_A,)
        _assert_terminal(update.sql, "failed")

    async def test_email_outbox_deliver_due_second_to_last_attempt_still_retries(self) -> None:
        """attempts == MAX_ATTEMPTS - 1 still backs off."""
        pool = _FakePool([_row(row_id=_ROW_A, attempts=MAX_ATTEMPTS - 1)])

        with _patch_deliver(_deliver_failing_for(_ALICE)):
            await deliver_due(pool, _config())

        assert _kind(_only_update(pool, _ROW_A).sql) == "retry"


class TestDeliverDueUnsendable:
    """Rows that can never be sent fail at once (no retry), scrubbed, never delivered."""

    @pytest.mark.parametrize(
        "row",
        [
            pytest.param(lambda: _row(stored={"org_name": _ORG_NAME}), id="missing-fields"),
            pytest.param(
                lambda: _row(
                    stored={
                        "org_name": _ORG_NAME,
                        "accept_link": _ACCEPT_LINK,
                        "expires_at": "2026-09-01T14:30:00Z",
                        "project_name": "Project Alpha",
                    }
                ),
                id="content-field",
            ),
            pytest.param(
                lambda: _row(
                    stored={
                        "org_name": _ORG_NAME,
                        "accept_link": "javascript:inv-tok-SECRET",
                        "expires_at": "2026-09-01T14:30:00Z",
                    }
                ),
                id="bad-link",
            ),
            pytest.param(lambda: _row(stored="{not json"), id="not-json"),
            pytest.param(lambda: _row(stored=[1, 2, 3]), id="json-array"),
            pytest.param(lambda: _row(template_key="newsletter"), id="unknown-template"),
            pytest.param(lambda: _row(language="it"), id="unknown-language"),
        ],
    )
    async def test_email_outbox_deliver_due_fails_unsendable_rows_at_once(
        self, row: Callable[[], dict[str, Any]]
    ) -> None:
        """Bad stored params, an unknown template or language: failed on the first attempt,
        params scrubbed, deliver never awaited."""
        pool = _FakePool([row()])
        deliver = AsyncMock()

        with _patch_deliver(deliver):
            sent = await deliver_due(pool, _config())

        assert sent == 0
        deliver.assert_not_awaited()
        update = _only_update(pool, _ROW_A)
        assert update.args == (_ROW_A,)
        _assert_terminal(update.sql, "failed")

    async def test_email_outbox_deliver_due_fails_on_build_error(self) -> None:
        """A build_message error (e.g. an address the stdlib refuses) fails the row at once."""
        pool = _FakePool([_row()])
        deliver = AsyncMock()
        build = MagicMock(side_effect=ValueError("Header values may not contain linefeed"))

        with _patch_deliver(deliver), patch("admino.email_outbox.mailer.build_message", build):
            await deliver_due(pool, _config())

        deliver.assert_not_awaited()
        _assert_terminal(_only_update(pool, _ROW_A).sql, "failed")


class TestDeliverDueBatch:
    """One failing row never stops the rest of the batch."""

    async def test_email_outbox_deliver_due_mixed_batch(self) -> None:
        """Unsendable A fails, B's delivery error backs off, C is sent: 1 sent."""
        rows = [
            _row(row_id=_ROW_A, address=_ALICE, template_key="newsletter"),
            _row(row_id=_ROW_B, address=_BOB, attempts=1),
            _row(row_id=_ROW_C, address=_CAROL),
        ]
        pool = _FakePool(rows)
        deliver = _deliver_failing_for(_BOB)

        with _patch_deliver(deliver):
            sent = await deliver_due(pool, _config())

        assert sent == 1
        assert sorted(str(m["To"]) for m in _delivered(deliver)) == sorted([_BOB, _CAROL])
        assert _kind(_only_update(pool, _ROW_A).sql) == "failed"
        assert _kind(_only_update(pool, _ROW_B).sql) == "retry"
        assert _kind(_only_update(pool, _ROW_C).sql) == "sent"

    async def test_email_outbox_deliver_due_first_failure_doesnt_stop_the_rest(self) -> None:
        """The first row's delivery error doesn't prevent the next ones."""
        rows = [
            _row(row_id=_ROW_A, address=_ALICE),
            _row(row_id=_ROW_B, address=_BOB),
            _row(row_id=_ROW_C, address=_CAROL),
        ]
        pool = _FakePool(rows)

        with _patch_deliver(_deliver_failing_for(_ALICE)):
            sent = await deliver_due(pool, _config())

        assert sent == 2
        assert _kind(_only_update(pool, _ROW_B).sql) == "sent"
        assert _kind(_only_update(pool, _ROW_C).sql) == "sent"


class TestDeliverDueLogging:
    """Failures are logged with the outbox id and the exception class name only."""

    async def test_email_outbox_deliver_due_failure_logs_id_and_class(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A WARNING that names the outbox id and the exception class."""
        caplog.set_level(logging.DEBUG)
        error = smtplib.SMTPRecipientsRefused({_ALICE: (550, b"no such user")})
        pool = _FakePool([_row(row_id=_ROW_A)])

        with _patch_deliver(AsyncMock(side_effect=error)):
            await deliver_due(pool, _config())

        assert any(
            str(_ROW_A) in record.getMessage() and "SMTPRecipientsRefused" in record.getMessage()
            for record in _warnings(caplog)
        )

    @pytest.mark.parametrize("make_error", _DELIVERY_ERRORS)
    @pytest.mark.parametrize("attempts", [1, MAX_ATTEMPTS], ids=["retry", "final"])
    async def test_email_outbox_deliver_due_failure_log_has_no_exception_text(
        self,
        make_error: Callable[[], Exception],
        attempts: int,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Never str(exc) or a traceback: SMTPRecipientsRefused carries the address, and it
        must not reach the log. Nor may the address, link, org name or credentials."""
        caplog.set_level(logging.DEBUG)
        pool = _FakePool([_row(row_id=_ROW_A, address=_ALICE, attempts=attempts)])

        with _patch_deliver(AsyncMock(side_effect=make_error())):
            await deliver_due(pool, _config())

        assert _warnings(caplog)
        _assert_absent(
            caplog,
            _ALICE,
            "no such user",
            "handshake failed",
            _ACCEPT_LINK,
            "inv-tok-SECRET",
            _ORG_NAME,
            _SMTP_USER,
            _SMTP_PASSWORD,
            _SMTP_FROM,
        )

    async def test_email_outbox_deliver_due_unsendable_log_has_no_input_echo(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A params ValidationError echoes its input: the log gets the class name only."""
        caplog.set_level(logging.DEBUG)
        stored = {
            "org_name": _ORG_NAME,
            "accept_link": "javascript:inv-tok-SECRET",
            "expires_at": "2026-09-01T14:30:00Z",
        }
        pool = _FakePool([_row(row_id=_ROW_A, stored=stored)])

        with _patch_deliver(AsyncMock()):
            await deliver_due(pool, _config())

        assert any(str(_ROW_A) in record.getMessage() for record in _warnings(caplog))
        _assert_absent(caplog, "inv-tok-SECRET", _ORG_NAME, _ALICE, "input_value")


# ---------------------------------------------------------------------------
# 4. purge_finished(): terminal rows past the retention
# ---------------------------------------------------------------------------


def _purge_sql(pool: MagicMock) -> tuple[str, tuple[Any, ...]]:
    """The normalized SQL and args of purge_finished()'s single execute."""
    assert pool.execute.await_count == 1
    call = pool.execute.await_args
    assert call is not None
    return _normalized(call.args[0]), tuple(call.args[1:])


class TestPurgeFinished:
    """purge_finished() deletes sent/failed rows finished more than N days ago."""

    async def test_email_outbox_purge_deletes_old_terminal_rows(self, mock_pool: MagicMock) -> None:
        """DELETE FROM email_outbox WHERE status IN ('sent', 'failed') AND finished_at <
        now() - make_interval(days => $1)."""
        mock_pool.execute = AsyncMock(return_value="DELETE 7")

        await purge_finished(mock_pool)

        sql, _ = _purge_sql(mock_pool)
        match = re.fullmatch(r"delete\s+from\s+email_outbox\s+where\s+(.*)", sql)
        assert match is not None, sql
        where = match.group(1)
        assert re.search(
            r"\bstatus\s+in\s*\(\s*(?:'sent'\s*,\s*'failed'|'failed'\s*,\s*'sent')\s*\)", where
        ), where
        assert re.search(
            rf"\bfinished_at\s*<\s*{_NOW}\s*-\s*make_interval\s*\(\s*days\s*=>\s*\$1{_CAST}\s*\)",
            where,
        ), where

    async def test_email_outbox_purge_defaults_to_thirty_days(self, mock_pool: MagicMock) -> None:
        """The retention is bound as $1, 30 by default."""
        mock_pool.execute = AsyncMock(return_value="DELETE 0")

        await purge_finished(mock_pool)

        _, args = _purge_sql(mock_pool)
        assert args == (FINISHED_RETENTION_DAYS,)

    @pytest.mark.parametrize("days", [1, 90, 3650])
    async def test_email_outbox_purge_binds_a_custom_retention(
        self, mock_pool: MagicMock, days: int
    ) -> None:
        """A custom retention within 1 to 3650 days is bound as $1."""
        mock_pool.execute = AsyncMock(return_value="DELETE 0")

        await purge_finished(mock_pool, days)

        _, args = _purge_sql(mock_pool)
        assert args == (days,)

    @pytest.mark.parametrize(
        ("status", "expected"), [("DELETE 7", 7), ("DELETE 0", 0), ("DELETE 12345", 12345)]
    )
    async def test_email_outbox_purge_returns_the_deleted_count(
        self, mock_pool: MagicMock, status: str, expected: int
    ) -> None:
        """The count parsed from asyncpg's status string."""
        mock_pool.execute = AsyncMock(return_value=status)

        assert await purge_finished(mock_pool) == expected

    @pytest.mark.parametrize(
        "days",
        [
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
            pytest.param(3651, id="over-ten-years"),
            pytest.param(True, id="bool"),
            pytest.param(1.5, id="float"),
            pytest.param(30.0, id="integral-float"),
            pytest.param("30", id="string"),
            pytest.param(None, id="none"),
        ],
    )
    async def test_email_outbox_purge_refuses_bad_retention(
        self, mock_pool: MagicMock, days: Any
    ) -> None:
        """A retention outside 1 to 3650 days, or not an int (a bool is refused): ValueError,
        before any database call."""
        with pytest.raises(ValueError, match=r".*"):
            await purge_finished(mock_pool, days)

        mock_pool.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# 5. run_outbox_sender(): the background loop
# ---------------------------------------------------------------------------


class _Clock:
    """A fake time.monotonic that only moves when a fake sleep advances it."""

    def __init__(self, start: float = 50_000.0) -> None:
        self.now = start

    def monotonic(self) -> float:
        """The current fake time."""
        return self.now


def _loop_sleep(
    events: list[str], *, advances: list[float], clock: _Clock | None = None
) -> AsyncMock:
    """A fake asyncio.sleep: advances the clock by the next amount, and raises CancelledError
    once the advances are used up (so the loop runs len(advances) + 1 iterations)."""
    calls = {"count": 0}

    async def fake_sleep(delay: float) -> None:
        events.append("sleep")
        if calls["count"] >= len(advances):
            raise asyncio.CancelledError
        if clock is not None:
            clock.now += advances[calls["count"]]
        calls["count"] += 1

    return AsyncMock(side_effect=fake_sleep)


def _recording(events: list[str], name: str, result: Any = 0) -> AsyncMock:
    """An AsyncMock that records its name in the event list."""

    async def fake(*_args: Any, **_kwargs: Any) -> Any:
        events.append(name)
        return result

    return AsyncMock(side_effect=fake)


def _iterations(events: list[str]) -> list[list[str]]:
    """Split the event list into loop iterations (each ends with a sleep)."""
    iterations: list[list[str]] = []
    current: list[str] = []
    for event in events:
        if event == "sleep":
            iterations.append(current)
            current = []
        else:
            current.append(event)
    return iterations


@contextlib.contextmanager
def _patched_sender(
    *, deliver: AsyncMock, purge: AsyncMock, sleep: AsyncMock, clock: _Clock | None = None
) -> Iterator[None]:
    """Patch deliver_due, purge_finished, asyncio.sleep and time.monotonic as the loop looks
    them up."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("admino.email_outbox.deliver_due", deliver))
        stack.enter_context(patch("admino.email_outbox.purge_finished", purge))
        stack.enter_context(patch("admino.email_outbox.asyncio.sleep", sleep))
        if clock is not None:
            stack.enter_context(patch("admino.email_outbox.time.monotonic", clock.monotonic))
        yield


def _arg(call: Any, index: int, name: str) -> Any:
    """A call argument, positional or keyword."""
    if len(call.args) > index:
        return call.args[index]
    return call.kwargs[name]


class TestRunOutboxSender:
    """The sender loop: deliver, sleep, repeat; purge daily; survive failures."""

    async def test_email_outbox_sender_delivers_then_sleeps_in_a_loop(self) -> None:
        """Every iteration runs one deliver_due pass, then sleeps."""
        events: list[str] = []
        clock = _Clock()

        with (
            _patched_sender(
                deliver=_recording(events, "deliver"),
                purge=_recording(events, "purge"),
                sleep=_loop_sleep(events, advances=[10, 10], clock=clock),
                clock=clock,
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        iterations = _iterations(events)
        assert [it.count("deliver") for it in iterations] == [1, 1, 1]

    async def test_email_outbox_sender_passes_pool_and_config(self) -> None:
        """deliver_due(pool, config) every time."""
        pool = MagicMock(name="pool")
        config = _config()
        deliver = AsyncMock(return_value=0)
        clock = _Clock()

        with (
            _patched_sender(
                deliver=deliver,
                purge=AsyncMock(return_value=0),
                sleep=_loop_sleep([], advances=[10], clock=clock),
                clock=clock,
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(pool, config)

        assert deliver.await_count == 2
        for call in deliver.await_args_list:
            assert _arg(call, 0, "pool") is pool
            assert _arg(call, 1, "config") is config

    async def test_email_outbox_sender_sleeps_the_poll_interval(self) -> None:
        """The default poll interval is POLL_INTERVAL_SECONDS (10 s)."""
        sleep = _loop_sleep([], advances=[10, 10])

        with (
            _patched_sender(
                deliver=AsyncMock(return_value=0),
                purge=AsyncMock(return_value=0),
                sleep=sleep,
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        delays = [_arg(call, 0, "delay") for call in sleep.await_args_list]
        assert delays == [POLL_INTERVAL_SECONDS] * 3

    async def test_email_outbox_sender_uses_a_custom_interval(self) -> None:
        """interval_seconds is keyword-only and passed to asyncio.sleep."""
        sleep = _loop_sleep([], advances=[])

        with (
            _patched_sender(
                deliver=AsyncMock(return_value=0),
                purge=AsyncMock(return_value=0),
                sleep=sleep,
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config(), interval_seconds=2.5)

        assert _arg(sleep.await_args_list[0], 0, "delay") == 2.5
        parameter = inspect.signature(run_outbox_sender).parameters["interval_seconds"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default == POLL_INTERVAL_SECONDS

    async def test_email_outbox_sender_purges_on_the_first_pass_only_until_a_day_passed(
        self,
    ) -> None:
        """Purge on the first iteration, then only once PURGE_INTERVAL_SECONDS have passed
        (by time.monotonic): 10 s and 86010 s later no purge, 86510 s later a purge."""
        events: list[str] = []
        clock = _Clock()

        with (
            _patched_sender(
                deliver=_recording(events, "deliver"),
                purge=_recording(events, "purge"),
                sleep=_loop_sleep(events, advances=[10, 86000, 500, 10], clock=clock),
                clock=clock,
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        iterations = _iterations(events)
        assert [it.count("purge") for it in iterations] == [1, 0, 0, 1, 0]
        assert [it.count("deliver") for it in iterations] == [1, 1, 1, 1, 1]

    async def test_email_outbox_sender_purges_the_pool_with_the_default_retention(self) -> None:
        """purge_finished(pool) with the default 30-day retention."""
        pool = MagicMock(name="pool")
        purge = AsyncMock(return_value=0)

        with (
            _patched_sender(
                deliver=AsyncMock(return_value=0),
                purge=purge,
                sleep=_loop_sleep([], advances=[]),
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(pool, _config())

        purge.assert_awaited_once()
        call = purge.await_args
        assert call is not None
        assert _arg(call, 0, "pool") is pool
        days = call.args[1] if len(call.args) > 1 else call.kwargs.get("retention_days")
        assert days in (None, FINISHED_RETENTION_DAYS)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("boom"), id="runtime-error"),
            pytest.param(lambda: OSError("connection refused"), id="os-error"),
            pytest.param(
                lambda: asyncpg.exceptions.ConnectionDoesNotExistError("closed"),
                id="postgres-connection",
            ),
            pytest.param(lambda: asyncpg.InterfaceError("pool is closing"), id="interface"),
            pytest.param(lambda: TimeoutError("timed out"), id="timeout"),
        ],
    )
    async def test_email_outbox_sender_survives_a_failed_pass(
        self, make_error: Callable[[], Exception]
    ) -> None:
        """A failing deliver_due doesn't stop the loop: it sleeps and tries again."""
        deliver = AsyncMock(side_effect=[make_error(), 0, 0])
        sleep = _loop_sleep([], advances=[10, 10])

        with (
            _patched_sender(
                deliver=deliver, purge=AsyncMock(return_value=0), sleep=sleep, clock=_Clock()
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        assert deliver.await_count == 3
        assert sleep.await_count == 3

    async def test_email_outbox_sender_failed_pass_still_purges(self) -> None:
        """A deliver_due failure on the first pass doesn't skip the first purge."""
        purge = AsyncMock(return_value=0)

        with (
            _patched_sender(
                deliver=AsyncMock(side_effect=RuntimeError("boom")),
                purge=purge,
                sleep=_loop_sleep([], advances=[]),
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        purge.assert_awaited_once()

    async def test_email_outbox_sender_failed_purge_still_delivers(self) -> None:
        """A purge failure doesn't skip that iteration's delivery or stop the loop."""
        events: list[str] = []
        clock = _Clock()

        async def failing_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            raise OSError("connection reset")

        with (
            _patched_sender(
                deliver=_recording(events, "deliver"),
                purge=AsyncMock(side_effect=failing_purge),
                sleep=_loop_sleep(events, advances=[10, 10], clock=clock),
                clock=clock,
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        iterations = _iterations(events)
        assert [it.count("deliver") for it in iterations] == [1, 1, 1]
        assert iterations[0].count("purge") == 1

    @pytest.mark.parametrize("failing", ["deliver", "purge"])
    async def test_email_outbox_sender_logs_failures_by_class_name(
        self, failing: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A failure is a WARNING naming the exception class, without its text (a database
        error echoes the failing row, address included)."""
        caplog.set_level(logging.DEBUG)
        error = asyncpg.exceptions.CheckViolationError(
            f"Failing row contains ({_ROW_A}, {_ALICE}, invitation, {_ACCEPT_LINK})"
        )
        deliver = AsyncMock(side_effect=error if failing == "deliver" else None, return_value=0)
        purge = AsyncMock(side_effect=error if failing == "purge" else None, return_value=0)

        with (
            _patched_sender(
                deliver=deliver, purge=purge, sleep=_loop_sleep([], advances=[]), clock=_Clock()
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        assert any("CheckViolationError" in record.getMessage() for record in _warnings(caplog))
        _assert_absent(caplog, _ALICE, _ACCEPT_LINK, "inv-tok-SECRET", "Failing row")

    async def test_email_outbox_sender_cancel_during_delivery_propagates(self) -> None:
        """CancelledError from deliver_due stops the loop (not treated as a failed pass)."""
        sleep = _loop_sleep([], advances=[10, 10, 10])

        with (
            _patched_sender(
                deliver=AsyncMock(side_effect=asyncio.CancelledError),
                purge=AsyncMock(return_value=0),
                sleep=sleep,
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        sleep.assert_not_awaited()

    async def test_email_outbox_sender_cancel_during_purge_propagates(self) -> None:
        """CancelledError from purge_finished stops the loop too."""
        sleep = _loop_sleep([], advances=[10, 10, 10])
        deliver = AsyncMock(return_value=0)

        with (
            _patched_sender(
                deliver=deliver,
                purge=AsyncMock(side_effect=asyncio.CancelledError),
                sleep=sleep,
                clock=_Clock(),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_outbox_sender(MagicMock(), _config())

        sleep.assert_not_awaited()
        assert deliver.await_count <= 1

    async def test_email_outbox_sender_task_cancel_stops_it(self) -> None:
        """Cancelling the sender's task while it sleeps ends the task as cancelled."""
        sleeping = asyncio.Event()

        async def blocking_sleep(_delay: float) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        with _patched_sender(
            deliver=AsyncMock(return_value=0),
            purge=AsyncMock(return_value=0),
            sleep=AsyncMock(side_effect=blocking_sleep),
        ):
            task = asyncio.create_task(run_outbox_sender(MagicMock(), _config()))
            async with asyncio.timeout(5):
                await sleeping.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert task.cancelled()


# ---------------------------------------------------------------------------
# 6. The server lifespan starts the sender only when SMTP is configured
# ---------------------------------------------------------------------------


def _make_app_config() -> MagicMock:
    """Build a minimal mock AppConfig for create_app (GH-149: no ``auth`` section)."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _LifespanProbe:
    """Fakes for the lifespan's pool, retention job, SMTP config loader and outbox sender."""

    def __init__(self, smtp_config: SmtpConfig | None) -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.smtp_config = smtp_config
        self.sender_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.sender_tasks: list[asyncio.Task[Any]] = []
        self.load_smtp_config = MagicMock(side_effect=self._load)

    def _load(self, *_args: Any, **_kwargs: Any) -> SmtpConfig | None:
        self.events.append("load_smtp_config")
        return self.smtp_config

    async def _blocking(self, name: str) -> None:
        """Block until cancelled, then finish after one more loop turn."""
        self.events.append(f"{name}-started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append(f"{name}-cancelled")
            await _REAL_SLEEP(0)
            self.events.append(f"{name}-finished")
            raise

    async def sender(self, *args: Any, **kwargs: Any) -> None:
        """The fake run_outbox_sender."""
        task = asyncio.current_task()
        assert task is not None
        self.sender_tasks.append(task)
        self.sender_calls.append((args, kwargs))
        await self._blocking("sender")

    async def retention(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_retention_job."""
        await self._blocking("retention")

    async def session_purge(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_session_purge_job (GH-152)."""
        await self._blocking("session-purge")

    async def org_purge(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_org_purge_job (GH-154)."""
        await self._blocking("org-purge")


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe) -> Iterator[None]:
    """Patch the lifespan's database calls, the retention job, the session purge job
    (GH-152), the org purge job (GH-154), the SMTP config loader and the outbox
    sender. get_pool() raises until init_pool() ran, like the real one. ``create=True``
    on the purge jobs: they are new, and these tests don't depend on them; the stubs
    keep the real purges from running against the MagicMock pool."""
    state: dict[str, Any] = {"pool": None}

    async def fake_init_pool(*_args: Any, **_kwargs: Any) -> Any:
        probe.events.append("init_pool")
        state["pool"] = probe.pool
        return probe.pool

    def fake_get_pool() -> Any:
        if state["pool"] is None:
            msg = "Database pool not initialised"
            raise RuntimeError(msg)
        return state["pool"]

    async def fake_close_pool() -> None:
        probe.events.append("close_pool")
        state["pool"] = None

    with (
        patch("admino.database.init_pool", fake_init_pool),
        patch("admino.database.close_pool", fake_close_pool),
        patch("admino.database.get_pool", fake_get_pool),
        patch("admino.database.load_permissions_from_db", AsyncMock(return_value={})),
        # GH-159: the tools gate reload never reads the MagicMock pool.
        patch_tools_gate(),
        patch("admino.audit_events.run_retention_job", probe.retention),
        patch("admino.mailer.load_smtp_config", probe.load_smtp_config),
        patch("admino.email_outbox.run_outbox_sender", probe.sender),
        patch("admino.sessions.run_session_purge_job", probe.session_purge, create=True),
        patch_org_purge_job(probe.org_purge),
        # GH-157: the login throttle purge never runs against the MagicMock pool.
        patch_login_throttle_purge_job(AsyncMock()),
    ):
        yield


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(5):
        await _REAL_SLEEP(0)


class TestLifespanStartsSender:
    """The lifespan runs the outbox sender while the app is up, when SMTP is configured."""

    async def test_email_outbox_lifespan_starts_sender_with_pool_and_config(self) -> None:
        """With a config, run_outbox_sender(get_pool(), config) runs as a task."""
        smtp_config = _config()
        probe = _LifespanProbe(smtp_config)
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert len(probe.sender_calls) == 1
                args, kwargs = probe.sender_calls[0]
                pool = args[0] if args else kwargs["pool"]
                config = args[1] if len(args) > 1 else kwargs["config"]
                assert pool is probe.pool
                assert config is smtp_config

    async def test_email_outbox_lifespan_loads_config_once_after_init_pool(self) -> None:
        """load_smtp_config() runs once on startup, after the pool exists, and the sender
        starts after that."""
        probe = _LifespanProbe(_config())
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert probe.load_smtp_config.call_count == 1
        assert probe.events.index("init_pool") < probe.events.index("load_smtp_config")
        assert probe.events.index("load_smtp_config") < probe.events.index("sender-started")

    async def test_email_outbox_lifespan_cancels_sender_on_shutdown(self) -> None:
        """On shutdown the sender's task is cancelled."""
        probe = _LifespanProbe(_config())
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert len(probe.sender_tasks) == 1
        assert probe.sender_tasks[0].cancelled()

    async def test_email_outbox_lifespan_awaits_sender_before_closing_pool(self) -> None:
        """The cancelled sender finishes before the pool closes, so it never runs against a
        closed pool."""
        probe = _LifespanProbe(_config())
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "sender-finished" in probe.events
        assert probe.events.index("sender-finished") < probe.events.index("close_pool")

    async def test_email_outbox_lifespan_keeps_the_retention_job(self) -> None:
        """The audit retention job still starts and stops before the pool closes."""
        probe = _LifespanProbe(_config())
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "retention-started" in probe.events
        assert "sender-started" in probe.events
        assert probe.events.index("retention-finished") < probe.events.index("close_pool")

    async def test_email_outbox_lifespan_without_smtp_starts_no_sender(self) -> None:
        """Without SMTP config (None) no sender starts, and the app still starts and stops:
        emails stay queued."""
        probe = _LifespanProbe(None)
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert probe.load_smtp_config.call_count == 1
                assert probe.sender_calls == []

        assert "sender-started" not in probe.events
        assert "close_pool" in probe.events


# ---------------------------------------------------------------------------
# 7. The log scan: no addresses, names, links or SMTP secrets anywhere
# ---------------------------------------------------------------------------


class TestLogScan:
    """The issue's log scan: run every path at DEBUG and look for content in the logs."""

    async def test_email_outbox_log_scan_finds_no_content(
        self, conn: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Enqueue, a successful pass, a failing pass (SMTPRecipientsRefused carries the
        address), a final failure, an unsendable row, and load_smtp_config with bad and
        missing values: no recipient address, SMTP username, password, from-address, link or
        org name appears in any record."""
        caplog.set_level(logging.DEBUG)
        config = _config()

        await enqueue_email(conn, user_id=_USER, params=_invitation())

        with _patch_deliver(AsyncMock()):
            await deliver_due(_FakePool([_row(row_id=_ROW_A, address=_ALICE)]), config)

        refused = smtplib.SMTPRecipientsRefused(
            {_BOB: (550, b"5.1.1 <" + _BOB.encode() + b">: recipient unknown")}
        )
        with _patch_deliver(AsyncMock(side_effect=refused)):
            await deliver_due(_FakePool([_row(row_id=_ROW_B, address=_BOB)]), config)
            await deliver_due(
                _FakePool([_row(row_id=_ROW_B, address=_BOB, attempts=MAX_ATTEMPTS)]), config
            )

        unsendable = {
            "org_name": _ORG_NAME,
            "accept_link": "javascript:inv-tok-SECRET",
            "expires_at": "2026-09-01T14:30:00Z",
        }
        with _patch_deliver(AsyncMock()):
            await deliver_due(
                _FakePool([_row(row_id=_ROW_C, address=_CAROL, stored=unsendable)]), config
            )

        load_smtp_config(
            {
                "SMTP_HOST": "bad host.invalid",
                "SMTP_PORT": "25",
                "SMTP_USERNAME": _SMTP_USER,
                "SMTP_PASSWORD": _SMTP_PASSWORD,
                "SMTP_FROM": _SMTP_FROM,
            }
        )
        load_smtp_config({"SMTP_USERNAME": _SMTP_USER, "SMTP_PASSWORD": _SMTP_PASSWORD})

        assert _warnings(caplog), "the failing paths must log warnings"
        _assert_absent(
            caplog,
            _ALICE,
            _BOB,
            _CAROL,
            "recipient unknown",
            _SMTP_USER,
            _SMTP_PASSWORD,
            _SMTP_FROM,
            _ACCEPT_LINK,
            "inv-tok-SECRET",
            _ORG_NAME,
            "bad host.invalid",
        )


# ---------------------------------------------------------------------------
# 8. Module isolation and hygiene
# ---------------------------------------------------------------------------

_ALLOWED_ADMINO: frozenset[str] = frozenset({"admino.email_templates", "admino.mailer"})
_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"asyncpg", "pydantic", "pydantic_core"})
_NEW_MODULES: tuple[str, ...] = ("email_templates.py", "mailer.py", "email_outbox.py")
_SQL_KEYWORD_RE = re.compile(r"\b(?:insert|select|delete|update)\b", re.IGNORECASE)


def _imported_modules(path: Path) -> list[str]:
    """Return every module a source file imports, with relative imports resolved under admino."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = f"admino.{base}" if base else "admino"
            if base == "admino":
                modules.extend(f"admino.{alias.name}" for alias in node.names)
            else:
                modules.append(base)
    return modules


def _formatted_sql_sites(path: Path) -> list[str]:
    """Return f-strings, %-formatting and .format() calls whose text looks like SQL."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    sites: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            text = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if _SQL_KEYWORD_RE.search(text):
                sites.append(f"line {node.lineno}: f-string")
        elif (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod | ast.Add)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and _SQL_KEYWORD_RE.search(node.left.value)
        ):
            sites.append(f"line {node.lineno}: %-format or concatenation")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
            and _SQL_KEYWORD_RE.search(node.func.value.value)
        ):
            sites.append(f"line {node.lineno}: str.format")
    return sites


def _sql_constants(path: Path) -> list[str]:
    """Every string constant in a source file that is SQL on email_outbox."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "email_outbox" in node.value.lower()
        and _SQL_KEYWORD_RE.search(node.value)
    ]


class TestModuleIsolation:
    """email_outbox.py stays small in its imports and builds no SQL from values."""

    def test_email_outbox_imports_only_allowed_modules(self) -> None:
        """Only the stdlib, asyncpg, pydantic, admino.email_templates and admino.mailer: no
        agent, server, llm*, tools, permissions or access import, and no new dependency."""
        disallowed = [
            module
            for module in _imported_modules(_SRC_DIR / "email_outbox.py")
            if not (
                module.split(".")[0] in sys.stdlib_module_names
                or module.split(".")[0] in _ALLOWED_THIRD_PARTY
                or module in _ALLOWED_ADMINO
            )
        ]

        assert disallowed == []

    def test_email_outbox_leaves_smtp_to_the_mailer(self) -> None:
        """No smtplib or ssl import: the transport lives in admino.mailer."""
        roots = {m.split(".")[0] for m in _imported_modules(_SRC_DIR / "email_outbox.py")}

        assert roots.isdisjoint({"smtplib", "ssl", "socket"})

    def test_email_outbox_uses_the_mailer_module_attribute(self) -> None:
        """``from admino import mailer`` (called as mailer.deliver / mailer.build_message), so
        the transport can be swapped and patched in one place."""
        assert getattr(outbox_mod, "mailer", None) is sys.modules["admino.mailer"]

    @pytest.mark.parametrize("module", _NEW_MODULES)
    def test_email_outbox_new_modules_make_no_dynamic_code_calls(self, module: str) -> None:
        """No eval, exec, compile, __import__, importlib or shell=True in the new modules."""
        tree = ast.parse((_SRC_DIR / module).read_text(encoding="utf-8"))
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]
        shells = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.keyword)
            and node.arg == "shell"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ]
        importlib = [m for m in _imported_modules(_SRC_DIR / module) if m.startswith("importlib")]

        assert calls == []
        assert shells == []
        assert importlib == []

    def test_email_outbox_builds_no_sql_by_string_formatting(self) -> None:
        """No f-string, %-format, concatenation or .format() produces SQL."""
        assert _formatted_sql_sites(_SRC_DIR / "email_outbox.py") == []

    def test_email_outbox_sql_uses_dollar_placeholders_only(self) -> None:
        """The SQL constants use $n bind parameters only: no %s, %(name)s, ? or {name}."""
        constants = _sql_constants(_SRC_DIR / "email_outbox.py")

        assert constants, "email_outbox.py must keep its SQL as string constants"
        for sql in constants:
            assert re.search(r"%s|%\(\w+\)|\?|\{\w+\}", sql) is None, sql
            assert re.search(r"\$\d", sql), sql

    def test_email_outbox_permission_engine_imports_none_of_them(self) -> None:
        """permissions.py gains no import of email_templates, mailer or email_outbox."""
        modules = _imported_modules(_SRC_DIR / "permissions.py")
        new = ("admino.email_templates", "admino.mailer", "admino.email_outbox")

        assert [m for m in modules if m.startswith(new)] == []

    def test_email_outbox_docstring_states_the_security_rules(self) -> None:
        """The module docstring documents that no address reaches the logs and that params
        are scrubbed."""
        doc = (outbox_mod.__doc__ or "").lower()

        assert "log" in doc
        assert "address" in doc


# ---------------------------------------------------------------------------
# cancel_pending: a resend's stale invitation email (GH-153)
# ---------------------------------------------------------------------------


class TestCancelPending:
    """cancel_pending() ends a recipient's pending emails of one template, clearing params."""

    async def test_email_outbox_cancel_pending_returns_the_count(self) -> None:
        from admino import email_outbox
        from admino.email_templates import EmailTemplate

        executor = MagicMock()
        executor.execute = AsyncMock(return_value="UPDATE 2")

        cancelled = await email_outbox.cancel_pending(
            executor, user_id=_USER, template=EmailTemplate.INVITATION
        )

        assert cancelled == 2
        assert executor.execute.await_count == 1

    async def test_email_outbox_cancel_pending_sql_scopes_and_scrubs(self) -> None:
        """One parameterized UPDATE: only this recipient's pending rows of the template,
        marked failed with params cleared and finished_at set (the finished-row invariant)."""
        from admino import email_outbox
        from admino.email_templates import EmailTemplate

        executor = MagicMock()
        executor.execute = AsyncMock(return_value="UPDATE 0")

        await email_outbox.cancel_pending(
            executor, user_id=_USER, template=EmailTemplate.INVITATION
        )

        sql, *args = executor.execute.await_args.args
        normalized = _normalized(sql)
        assert normalized.startswith("update email_outbox set ")
        assert "status = 'failed'" in normalized
        assert re.search(r"params = '\{\}'(::jsonb)?", normalized)
        assert "finished_at = now()" in normalized
        assert re.search(r"recipient_user_id = \$\d", normalized)
        assert re.search(r"template_key = \$\d", normalized)
        assert "status = 'pending'" in normalized
        assert args.count(_USER) == 1
        assert "invitation" in args
