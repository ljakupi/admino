"""Tests for admino.audit_events — the content-free audit event store (GH-146, GH-152, GH-153,
GH-161, GH-164, GH-166).

Every security-relevant action (logins, lockouts, password resets, invitations,
role changes, activations, sharing changes, deletions and restores, exports,
Org Admin access to other users' projects, org and platform settings, every
Super Admin action, residency policy, break-glass sessions, agent tool calls,
since GH-152 a user revoking one of their sessions and an Org Admin's forced
logout, since GH-153 an invitation sent again, and since GH-161 an Org Admin
changing, promoting, demoting or cancelling the promotion of one of the org's
tool permissions, since GH-164 an Org Admin changing a user's name or email,
and since GH-166 a user changing their own password)
is recorded through one
service function, record(), as a row in the append-only audit_events table
(migration 0005, tests/test_migration_0005.py).

What these tests pin down:
- The action catalog is a closed enum, and every action has exactly one org
  scope: org-scoped actions need an org_id (so a Super Admin action affecting an
  org lands in that org's log, where its admins see it), platform-scoped ones
  must have none, and a few (logins, account lifecycle) may have either.
- AuditEvent (a SealedModel) enforces the actor rules, UUID-only targets, a
  best-effort IP, and the metadata content validator: only bools, ints within
  +/-(2**53 - 1), None, UUID objects and tokens from a closed vocabulary (member
  roles, permission decisions, tool names and actions) are accepted. Free text,
  names, titles, file names, emails, lookalike tokens, UUID strings, floats and
  containers are refused.
- record() issues exactly one parameterized INSERT. A validation or write
  failure raises AuditRecordError (never swallowed), so the caller's transaction
  rolls back and the action doesn't proceed silently.
- purge_expired() validates the retention (6 to 84 months, default 12), runs
  purge_audit_events($1) and records one audit.purge event in the same
  transaction. run_retention_job() runs it daily and survives failures, and the
  server lifespan starts it and cancels it before closing the pool. GH-160:
  run_retention_job(pool, *, retention_months, interval_seconds) takes a
  required zero-argument async callable, awaited before each purge (a changed
  value applies to the next run; a failing lookup is logged by class name and
  retried next interval); the lifespan passes one that returns the cached
  platform settings' retention.audit_months. (The
  lifespan helper here also stubs GH-152's session purge job, which
  tests/test_session_management_api.py covers.)
- GH-161: four org-scoped actions, ``org.permission_change``,
  ``org.permission_promote``, ``org.permission_promote_cancel`` and
  ``org.permission_demote`` (47 in all). Their metadata is tokens only:
  ``{"tool", "action", "old", "new"}`` for a change, a promotion (deny ->
  confirm) and a demotion (confirm -> deny), ``{"tool", "action"}`` for a
  cancelled promotion. A tool or action name outside the vocabulary (free
  text such as "Gmail Send") is refused like any other content.
- GH-164: one more org-scoped action, ``user.profile_change`` (48 in all): an
  Org Admin changed a user's name and/or email (metadata ``{"name_changed":
  bool, "email_changed": bool}``), or the email change was refused because the
  address is taken (``{"email_taken": True}``). The target is the user; the
  name and the email are never in the row: a metadata value that is an email
  address or a name is refused by the existing content validator.
- GH-166: one more any-scoped action, ``password.change`` (49 in all): a user
  changed their own password from the account page, which ended their
  sessions. A member's event carries their org; a Super Admin's has none. The
  target is the user themself; the metadata is ``{"sessions_revoked": int}``
  only: the password, the hash and the email are never in the row (free text
  is refused by the existing content validator). Self-service profile edits
  (name, languages, timezone, personal instructions) are not audited.

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- No content in audit events, errors or logs (tracker #139 §5): only IDs,
  counts, sizes, statuses. AuditRecordError is raised "from None", so Pydantic's
  error (which echoes the input) never travels with it, and it carries no IDs
  or metadata values.
- Parameterized SQL only: values travel as bind parameters, never in the SQL
  text. The app never sets id or occurred_at (the DB defaults do: no backdating).
- audit_events.py stays out of the server, agent, LLM, tools, OAuth and NDJSON
  audit layers; the permission engine (permissions.py) gains no import from it.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import json
import logging
import re
import sys
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import TYPE_CHECKING, Any, get_args
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import asyncpg
import pytest
from pydantic import SecretStr, ValidationError

import admino.audit_events as audit_events_mod
from admino import scoped_settings
from admino.access import SealedModel
from admino.audit_events import (
    ACTION_SCOPES,
    DEFAULT_RETENTION_MONTHS,
    MAX_RETENTION_MONTHS,
    METADATA_VOCABULARY,
    MIN_RETENTION_MONTHS,
    PURGE_INTERVAL_SECONDS,
    AuditAction,
    AuditEvent,
    AuditRecordError,
    TargetType,
    purge_expired,
    record,
    run_retention_job,
)
from admino.permissions import DEFAULT_PERMISSIONS, HARDCODED_DENIALS, PROMOTABLE_DENIALS
from admino.server import _lifespan, create_app
from tests.conftest import default_test_platform_settings
from tests.lifespan_stubs import (
    patch_login_throttle_purge_job,
    patch_org_purge_job,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ORG = UUID("3f2b8c1e-5d4a-4e7b-9a6c-0b1d2e3f4a5b")
_OTHER_ORG = UUID("7c9d0e1f-2a3b-4c5d-8e6f-a1b2c3d4e5f6")
_USER = UUID("a4b5c6d7-e8f9-4a0b-9c1d-2e3f4a5b6c7d")
_SUPER_ADMIN = UUID("b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e")
_PROJECT = UUID("c8d9e0f1-a2b3-4c4d-9e5f-6a7b8c9d0e1f")
_FILE = UUID("d2e3f4a5-b6c7-4d8e-8f9a-0b1c2d3e4f5a")
_MARKER = UUID("e5f6a7b8-c9d0-4e1f-9a2b-3c4d5e6f7a8b")
_IP = "203.0.113.7"
_MARKER_COUNT = 987654321

# Characters built with chr() so they survive editing tools verbatim.
_NUL = chr(0x00)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_CARRIAGE_RETURN = chr(0x0D)
_O_CIRCUMFLEX = chr(0x00F4)
_COMBINING_ACUTE = chr(0x0301)
_CYRILLIC_IE = chr(0x0435)  # looks like a Latin "e"
_CYRILLIC_O = chr(0x043E)  # looks like a Latin "o"
_ZERO_WIDTH_SPACE = chr(0x200B)
_ZERO_WIDTH_JOINER = chr(0x200D)
_RTL_OVERRIDE = chr(0x202E)
_BYTE_ORDER_MARK = chr(0xFEFF)
_FULLWIDTH_E = chr(0xFF45)

_SRC_DIR = Path(audit_events_mod.__file__).resolve().parent

# The real asyncio.sleep, kept before any test patches the module attribute.
_REAL_SLEEP = asyncio.sleep

_TEST_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"


# ---------------------------------------------------------------------------
# The spec's action catalog and scopes
# ---------------------------------------------------------------------------

_ORG_SCOPED: frozenset[str] = frozenset(
    {
        "invitation.create",
        "invitation.revoke",
        "invitation.accept",
        "user.role_change",
        "project.share",
        "project.unshare",
        "project.member_role_change",
        "project.transfer",
        "project.delete",
        "project.restore",
        "project.admin_access",
        "chat.delete",
        "chat.restore",
        "file.delete",
        "file.restore",
        "export.create",
        "org.settings_change",
        "org.create",
        "org.limits_change",
        "org.deactivate",
        "org.reactivate",
        "org.deletion_schedule",
        "org.deletion_cancel",
        "org.residency_change",
        "breakglass.start",
        "breakglass.end",
        "tool.call",
        # GH-152: an Org Admin logs a user of their org out.
        "session.force_logout",
        # GH-153: an Org Admin sends a pending invitation again with a new link.
        "invitation.resend",
        # GH-153: a refused send (email taken, no free seat), so probing shows in the log.
        "invitation.refuse",
        # GH-161: an Org Admin changes, promotes, demotes or cancels the promotion of
        # one of the org's tool permissions.
        "org.permission_change",
        "org.permission_promote",
        "org.permission_promote_cancel",
        "org.permission_demote",
        # GH-164: an Org Admin changes a user's name or email (or the change is refused
        # because the email is taken).
        "user.profile_change",
    }
)
_PLATFORM_SCOPED: frozenset[str] = frozenset(
    {"org.purge", "platform.settings_change", "model.registry_change", "audit.purge"}
)
_ANY_SCOPED: frozenset[str] = frozenset(
    {
        "login.success",
        "login.failure",
        "login.lockout",
        "password_reset.request",
        "password_reset.complete",
        "user.activate",
        "user.deactivate",
        "user.delete",
        # GH-152: a user (member or Super Admin) deletes one of their own sessions.
        "session.revoke",
        # GH-166: a user changes their own password from the account page.
        "password.change",
    }
)
_CATALOG: frozenset[str] = _ORG_SCOPED | _PLATFORM_SCOPED | _ANY_SCOPED

_SCOPE_CASES: list[Any] = [
    *(pytest.param(value, "org", id=value) for value in sorted(_ORG_SCOPED)),
    *(pytest.param(value, "platform", id=value) for value in sorted(_PLATFORM_SCOPED)),
    *(pytest.param(value, "any", id=value) for value in sorted(_ANY_SCOPED)),
]

# Every category the issue requires the catalog to cover.
_ISSUE_CATEGORIES: list[Any] = [
    pytest.param({"login.success", "login.failure"}, id="logins-success-and-failure"),
    pytest.param({"login.lockout"}, id="lockouts"),
    pytest.param({"password_reset.request", "password_reset.complete"}, id="password-resets"),
    pytest.param({"password.change"}, id="password-changes"),
    pytest.param(
        {
            "invitation.create",
            "invitation.revoke",
            "invitation.accept",
            "invitation.resend",
            "invitation.refuse",
        },
        id="invitations",
    ),
    pytest.param({"user.role_change", "project.member_role_change"}, id="role-changes"),
    pytest.param({"user.profile_change"}, id="user-profile-changes"),
    pytest.param({"user.activate"}, id="activations"),
    pytest.param({"user.deactivate"}, id="deactivations"),
    pytest.param(
        {"project.share", "project.unshare", "project.member_role_change", "project.transfer"},
        id="project-sharing-changes",
    ),
    pytest.param(
        {"project.delete", "chat.delete", "file.delete", "user.delete"},
        id="deletions",
    ),
    pytest.param({"project.restore", "chat.restore", "file.restore"}, id="restores"),
    pytest.param({"export.create"}, id="exports"),
    pytest.param({"project.admin_access"}, id="org-admin-access-to-other-users-projects"),
    pytest.param({"org.settings_change"}, id="org-settings-changes"),
    pytest.param(
        {
            "org.create",
            "org.limits_change",
            "org.deactivate",
            "org.reactivate",
            "org.deletion_schedule",
            "org.deletion_cancel",
            "org.purge",
            "platform.settings_change",
            "model.registry_change",
        },
        id="super-admin-actions",
    ),
    pytest.param({"org.residency_change"}, id="residency-policy-changes"),
    pytest.param({"breakglass.start", "breakglass.end"}, id="break-glass-sessions"),
    pytest.param({"tool.call"}, id="agent-tool-calls"),
    pytest.param({"audit.purge"}, id="retention-purge"),
    pytest.param(
        {"session.revoke", "session.force_logout"}, id="session-revocations-and-forced-logouts"
    ),
    pytest.param(
        {
            "org.permission_change",
            "org.permission_promote",
            "org.permission_promote_cancel",
            "org.permission_demote",
        },
        id="org-tool-permission-changes",
    ),
]

# Super Admin actions that affect one org: stored with that org's id.
_SUPER_ADMIN_ORG_ACTIONS: list[Any] = [
    pytest.param(AuditAction(value), id=value)
    for value in (
        "org.create",
        "org.limits_change",
        "org.deactivate",
        "org.reactivate",
        "org.deletion_schedule",
        "org.deletion_cancel",
        "org.residency_change",
        "breakglass.start",
        "breakglass.end",
    )
]


# ---------------------------------------------------------------------------
# Metadata validator inputs
# ---------------------------------------------------------------------------

_ACCEPTED_VALUES: list[Any] = [
    *(pytest.param(token, id=f"role-{token}") for token in ("org_admin", "editor", "viewer")),
    *(pytest.param(token, id=f"decision-{token}") for token in ("allow", "confirm", "deny")),
    *(
        pytest.param(token, id=f"tool-{token}")
        for token in (
            "gmail",
            "google_calendar",
            "google_drive",
            "outlook",
            "outlook_calendar",
            "onedrive",
            "memory",
            "documents",
        )
    ),
    *(
        pytest.param(token, id=f"action-{token}")
        for token in (
            "read",
            "list",
            "search",
            "send",
            "delete",
            "create",
            "update",
            "download",
            "store",
            "recall",
        )
    ),
    pytest.param(True, id="bool-true"),
    pytest.param(False, id="bool-false"),
    pytest.param(0, id="int-zero"),
    pytest.param(1, id="int-one"),
    pytest.param(-1, id="int-negative"),
    pytest.param(4096, id="int-size"),
    pytest.param(2**53 - 1, id="int-max-safe"),
    pytest.param(-(2**53 - 1), id="int-min-safe"),
    pytest.param(None, id="none"),
]

_REJECTED_VALUES: list[Any] = [
    pytest.param("Quarterly report", id="free-text"),
    pytest.param("Hello world", id="free-text-greeting"),
    pytest.param("Project Alpha", id="project-title"),
    pytest.param("Q3 Budget Review", id="title"),
    pytest.param("alice@example.com", id="email"),
    pytest.param("bob.smith@corp.example", id="email-dotted"),
    pytest.param("report.pdf", id="file-name"),
    pytest.param("invoice_2026.docx", id="file-name-underscore"),
    pytest.param("Alice", id="name-capitalized"),
    pytest.param("alice", id="name-lowercase"),
    pytest.param("bob", id="name-lowercase-bob"),
    pytest.param("secret", id="token-shaped-not-in-vocabulary"),
    pytest.param("hunter2", id="password-like-token"),
    pytest.param("", id="empty"),
    pytest.param(" editor", id="leading-space"),
    pytest.param("editor ", id="trailing-space"),
    pytest.param("editor" + _NEWLINE, id="trailing-newline"),
    pytest.param(_TAB + "editor", id="leading-tab"),
    pytest.param("allow" + _CARRIAGE_RETURN, id="trailing-carriage-return"),
    pytest.param("editor" + _NUL, id="nul-byte"),
    pytest.param("Editor", id="case-variant-role"),
    pytest.param("ALLOW", id="case-variant-decision"),
    pytest.param("Gmail", id="case-variant-tool"),
    pytest.param(_CYRILLIC_IE + "ditor", id="cyrillic-lookalike"),
    pytest.param(_FULLWIDTH_E + "ditor", id="fullwidth-lookalike"),
    pytest.param("e" + _COMBINING_ACUTE + "ditor", id="combining-mark"),
    pytest.param("editor" + _ZERO_WIDTH_SPACE, id="zero-width-space"),
    pytest.param("edi" + _ZERO_WIDTH_JOINER + "tor", id="zero-width-joiner"),
    pytest.param(_BYTE_ORDER_MARK + "editor", id="byte-order-mark"),
    pytest.param(_RTL_OVERRIDE + "editor", id="bidi-override"),
    pytest.param("editor" * 20, id="long-repeated-token"),
    pytest.param("editor,viewer", id="token-list-in-a-string"),
    pytest.param(str(_PROJECT), id="uuid-string"),
    pytest.param(str(_PROJECT).upper(), id="uuid-string-upper"),
    pytest.param("1", id="numeric-string"),
    pytest.param("true", id="boolean-string"),
    pytest.param("login.success", id="action-value-string"),
    pytest.param(AuditAction.LOGIN_SUCCESS, id="enum-member-not-in-vocabulary"),
    pytest.param(1.0, id="float-integral"),
    pytest.param(0.5, id="float"),
    pytest.param(float("nan"), id="float-nan"),
    pytest.param(float("inf"), id="float-inf"),
    pytest.param(Decimal(1), id="decimal"),
    pytest.param(["editor"], id="list"),
    pytest.param(("editor",), id="tuple"),
    pytest.param({"role": "editor"}, id="nested-dict"),
    pytest.param({"editor"}, id="set"),
    pytest.param(frozenset({"editor"}), id="frozenset"),
    pytest.param(b"editor", id="bytes"),
    pytest.param(bytearray(b"editor"), id="bytearray"),
    pytest.param(datetime(2026, 9, 26, tzinfo=UTC), id="datetime"),
    pytest.param(date(2026, 9, 26), id="date"),
    pytest.param(IPv4Address(_IP), id="ip-address-object"),
    pytest.param(2**53, id="int-above-safe-range"),
    pytest.param(-(2**53), id="int-below-safe-range"),
    pytest.param(10**30, id="huge-int"),
    pytest.param(object(), id="arbitrary-object"),
]

_ACCEPTED_KEYS: list[Any] = [
    pytest.param("a", id="single-letter"),
    pytest.param("x1", id="letter-digit"),
    pytest.param("old_role", id="old-role"),
    pytest.param("new_role", id="new-role"),
    pytest.param("size_bytes", id="size-bytes"),
    pytest.param("a" * 40, id="forty-chars"),
]

_REJECTED_KEYS: list[Any] = [
    pytest.param("Old_role", id="capitalized"),
    pytest.param("OLD_ROLE", id="upper-case"),
    pytest.param("old role", id="space"),
    pytest.param("old-role", id="hyphen"),
    pytest.param("old.role", id="dot"),
    pytest.param("user@example", id="at-sign"),
    pytest.param("1role", id="leading-digit"),
    pytest.param("_role", id="leading-underscore"),
    pytest.param("a" * 41, id="forty-one-chars"),
    pytest.param("", id="empty"),
    pytest.param("r" + _O_CIRCUMFLEX + "le", id="non-ascii"),
    pytest.param("r" + _CYRILLIC_O + "le", id="cyrillic-lookalike"),
    pytest.param("role" + _ZERO_WIDTH_SPACE, id="zero-width-space"),
    pytest.param("role" + _NEWLINE, id="trailing-newline"),
]

_NON_MAPPING_METADATA: list[Any] = [
    pytest.param("role=editor", id="string"),
    pytest.param(["role", "editor"], id="list"),
    pytest.param([("role", "editor")], id="list-of-pairs"),
    pytest.param(42, id="int"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(**overrides: Any) -> AuditEvent:
    """Build an AuditEvent through validation: a member deleting a project, by default."""
    fields: dict[str, Any] = {
        "org_id": _ORG,
        "actor_kind": "member",
        "actor_user_id": _USER,
        "action": AuditAction.PROJECT_DELETE,
        "target_type": TargetType.PROJECT,
        "target_ids": (_PROJECT,),
        "metadata": {},
    }
    fields.update(overrides)
    return AuditEvent(**fields)


def _record_kwargs(**overrides: Any) -> dict[str, Any]:
    """Keyword arguments for record(): a member deleting a project, by default."""
    kwargs: dict[str, Any] = {
        "action": AuditAction.PROJECT_DELETE,
        "actor_kind": "member",
        "actor_user_id": _USER,
        "org_id": _ORG,
        "target_type": TargetType.PROJECT,
        "target_ids": [_PROJECT],
        "ip": _IP,
        "metadata": {"role": "editor"},
    }
    kwargs.update(overrides)
    return kwargs


async def _record(executor: Any, **overrides: Any) -> None:
    """Call record() with the default event, overridden by keyword."""
    await record(executor, **_record_kwargs(**overrides))


def _normalized(sql: str) -> str:
    """Collapse whitespace, lowercase and drop a trailing semicolon, so SQL checks ignore
    formatting."""
    return re.sub(r"\s+", " ", sql).strip().rstrip(";").strip().lower()


_INSERT_RE = re.compile(r"^insert into audit_events\s*\(([^)]*)\)\s*values\s*\((.*)\)$")
_PLACEHOLDER_RE = re.compile(r"\$(\d+)(?:\s*::\s*[a-z_]+(?:\[\])?)?")


def _insert_call(executor: MagicMock) -> tuple[str, list[str], list[str], tuple[Any, ...]]:
    """Return (normalized SQL, columns, VALUES items, bind args) of record()'s one execute."""
    assert executor.execute.await_count == 1, "record() must issue exactly one execute"
    call = executor.execute.await_args
    assert call is not None
    sql = _normalized(call.args[0])
    match = _INSERT_RE.match(sql)
    assert match is not None, f"record() issued an unexpected statement: {sql}"
    columns = [column.strip().strip('"') for column in match.group(1).split(",")]
    values = [value.strip() for value in match.group(2).split(",")]
    return sql, columns, values, tuple(call.args[1:])


def _inserted_row(executor: MagicMock) -> dict[str, Any]:
    """Map each INSERT column to the bind argument its $n placeholder refers to."""
    _, columns, values, args = _insert_call(executor)
    assert len(columns) == len(values)
    row: dict[str, Any] = {}
    for column, value in zip(columns, values, strict=True):
        placeholder = _PLACEHOLDER_RE.fullmatch(value)
        assert placeholder is not None, f"{column} is not bound to a $n placeholder: {value}"
        row[column] = args[int(placeholder.group(1)) - 1]
    return row


def _content_markers(*values: object) -> list[str]:
    """Return the strings that must not appear: canonical and hex forms of UUIDs, str of others."""
    markers: list[str] = []
    for value in values:
        if isinstance(value, UUID):
            markers.extend([str(value), value.hex])
        else:
            markers.append(str(value))
    return markers


def _assert_no_content(text: str, *values: object) -> None:
    """Assert no ID or input value appears in a message, repr or log text."""
    for marker in _content_markers(*values):
        assert marker not in text, f"{marker!r} leaked into {text!r}"


def _transaction(conn: MagicMock) -> AsyncMock:
    """Give a mocked connection a transaction() async context manager and return it."""
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return txn


def _failing_row_message() -> str:
    """A realistic PostgreSQL error text: it echoes the row, IDs and values included."""
    return (
        "new row violates check constraint; Failing row contains "
        f"({_ORG}, {_USER}, member, project.delete, project, [{_PROJECT}], {_IP}, "
        f"project_id {_MARKER}, count {_MARKER_COUNT})"
    )


def _db_error_factories() -> list[Any]:
    """Factories for the errors a database write can raise (fresh instance per test)."""
    return [
        pytest.param(
            lambda: asyncpg.exceptions.CheckViolationError(_failing_row_message()),
            id="check-violation",
        ),
        pytest.param(
            lambda: asyncpg.exceptions.RaiseError(_failing_row_message()),
            id="trigger-raise",
        ),
        pytest.param(
            lambda: asyncpg.exceptions.ForeignKeyViolationError(_failing_row_message()),
            id="foreign-key-violation",
        ),
        pytest.param(
            lambda: asyncpg.exceptions.ConnectionDoesNotExistError(_failing_row_message()),
            id="connection-lost",
        ),
        pytest.param(
            lambda: asyncpg.InterfaceError(_failing_row_message()),
            id="interface-error",
        ),
        pytest.param(lambda: OSError(_failing_row_message()), id="os-error"),
        pytest.param(lambda: ConnectionResetError(_failing_row_message()), id="connection-reset"),
        pytest.param(lambda: TimeoutError(_failing_row_message()), id="timeout"),
    ]


def _purge_months(call: Any) -> Any:
    """Return the retention_months a purge_expired call received (positional or keyword)."""
    if len(call.args) > 1:
        return call.args[1]
    return call.kwargs["retention_months"]


def _purge_pool(call: Any) -> Any:
    """Return the pool a purge_expired call received (positional or keyword)."""
    if call.args:
        return call.args[0]
    return call.kwargs["pool"]


def _sleep_delay(call: Any) -> Any:
    """Return the delay an asyncio.sleep call received (positional or keyword)."""
    if call.args:
        return call.args[0]
    return call.kwargs["delay"]


def _cancelling_sleep(after: int, events: list[str] | None = None) -> AsyncMock:
    """A fake asyncio.sleep that returns at once and raises CancelledError on call `after`."""
    calls = {"count": 0}

    async def fake_sleep(delay: float) -> None:
        calls["count"] += 1
        if events is not None:
            events.append("sleep")
        if calls["count"] >= after:
            raise asyncio.CancelledError

    return AsyncMock(side_effect=fake_sleep)


@contextlib.contextmanager
def _patched_job(purge: AsyncMock, sleep: AsyncMock) -> Iterator[None]:
    """Patch purge_expired and asyncio.sleep as run_retention_job looks them up."""
    with (
        patch("admino.audit_events.purge_expired", purge),
        patch("admino.audit_events.asyncio.sleep", sleep),
    ):
        yield


@pytest.fixture()
def conn() -> MagicMock:
    """A mocked asyncpg connection whose execute succeeds."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.execute = AsyncMock(return_value="INSERT 0 1")
    connection.executemany = AsyncMock(return_value=None)
    connection.fetch = AsyncMock(return_value=[])
    connection.fetchrow = AsyncMock(return_value=None)
    connection.fetchval = AsyncMock(return_value=None)
    return connection


# ---------------------------------------------------------------------------
# 1. The action catalog (closed enum) and the other enumerations
# ---------------------------------------------------------------------------


class TestActionCatalog:
    """AuditAction is the closed catalog of auditable actions the issue lists."""

    def test_audit_events_action_is_a_str_enum(self) -> None:
        """AuditAction is a StrEnum, so its members bind as plain strings."""
        assert issubclass(AuditAction, StrEnum)

    def test_audit_events_action_catalog_is_exactly_the_spec(self) -> None:
        """The catalog has exactly the 49 actions of the spec (GH-146's 39, GH-152's
        session.revoke and session.force_logout, GH-153's invitation.resend and
        invitation.refuse, GH-161's four org.permission_* actions, GH-164's
        user.profile_change, GH-166's password.change): nothing missing, nothing
        extra."""
        assert {action.value for action in AuditAction} == _CATALOG
        assert len(AuditAction) == 49

    @pytest.mark.parametrize("value", sorted(_CATALOG))
    def test_audit_events_action_member_name_is_upper_snake_of_value(self, value: str) -> None:
        """Member names are the upper-snake form of the value (login.success -> LOGIN_SUCCESS)."""
        assert AuditAction(value).name == value.upper().replace(".", "_")

    @pytest.mark.parametrize("value", sorted(_CATALOG))
    def test_audit_events_action_value_is_a_dotted_lowercase_token(self, value: str) -> None:
        """Each value is '<noun>.<verb>' in lowercase snake case, at most 64 characters."""
        assert re.fullmatch(r"[a-z][a-z_]*\.[a-z][a-z_]*", AuditAction(value).value)
        assert len(value) <= 64

    @pytest.mark.parametrize("required", _ISSUE_CATEGORIES)
    def test_audit_events_action_catalog_covers_issue_category(self, required: set[str]) -> None:
        """Every category of the issue's action catalog is covered."""
        assert required <= {action.value for action in AuditAction}

    @pytest.mark.parametrize(
        "unknown", ["user.impersonate", "login", "LOGIN.SUCCESS", "project.read", ""]
    )
    def test_audit_events_action_unknown_value_is_refused(self, unknown: str) -> None:
        """A value outside the catalog is not an AuditAction."""
        with pytest.raises(ValueError):
            AuditAction(unknown)

    @pytest.mark.parametrize("unknown", ["user.impersonate", "project.read", "Login.Success"])
    def test_audit_events_event_with_unknown_action_is_rejected(self, unknown: str) -> None:
        """An AuditEvent can't carry an action outside the catalog."""
        with pytest.raises(ValidationError):
            _event(action=unknown, actor_kind="system", actor_user_id=None, org_id=None)

    def test_audit_events_target_type_is_exactly_the_spec(self) -> None:
        """TargetType is a StrEnum of the seven target kinds."""
        assert issubclass(TargetType, StrEnum)
        assert {target.value for target in TargetType} == {
            "organization",
            "user",
            "invitation",
            "project",
            "chat",
            "file",
            "model",
        }

    def test_audit_events_actor_kind_is_exactly_the_spec(self) -> None:
        """ActorKind is the Literal of the four actor kinds."""
        assert set(get_args(audit_events_mod.ActorKind)) == {
            "member",
            "super_admin",
            "system",
            "operator",
        }


# ---------------------------------------------------------------------------
# 2. Action scopes (which actions need an org_id and which must have none)
# ---------------------------------------------------------------------------


class TestActionScopes:
    """ACTION_SCOPES assigns every action exactly one scope, and AuditEvent enforces it."""

    def test_audit_events_scopes_cover_every_action(self) -> None:
        """ACTION_SCOPES is total over AuditAction and has no other keys."""
        assert set(ACTION_SCOPES) == set(AuditAction)

    def test_audit_events_scopes_use_only_known_scopes(self) -> None:
        """Every scope is 'org', 'platform' or 'any'."""
        assert set(ACTION_SCOPES.values()) <= {"org", "platform", "any"}

    @pytest.mark.parametrize(("value", "scope"), _SCOPE_CASES)
    def test_audit_events_scope_of_action_matches_spec(self, value: str, scope: str) -> None:
        """Each action has the scope the spec assigns to it."""
        assert ACTION_SCOPES[AuditAction(value)] == scope

    @pytest.mark.parametrize("value", sorted(_ORG_SCOPED))
    def test_audit_events_org_scoped_action_without_org_is_rejected(self, value: str) -> None:
        """An org-scoped action needs an org_id, even from a Super Admin (whose actions
        affecting an org must land in that org's log)."""
        action = AuditAction(value)

        with pytest.raises(ValidationError):
            _event(
                action=action,
                actor_kind="super_admin",
                actor_user_id=_SUPER_ADMIN,
                org_id=None,
                target_type=None,
                target_ids=(),
            )

    @pytest.mark.parametrize("value", sorted(_ORG_SCOPED))
    def test_audit_events_org_scoped_action_by_super_admin_keeps_org(self, value: str) -> None:
        """A Super Admin's org-scoped action is stored with the org's id."""
        event = _event(
            action=value,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=_ORG,
            target_type=None,
            target_ids=(),
        )

        assert event.org_id == _ORG

    @pytest.mark.parametrize("value", sorted(_ORG_SCOPED))
    def test_audit_events_org_scoped_action_by_member_is_valid(self, value: str) -> None:
        """A member's org-scoped action with the member's org is valid."""
        event = _event(action=value, target_type=None, target_ids=())

        assert event.action == AuditAction(value)

    @pytest.mark.parametrize("value", sorted(_PLATFORM_SCOPED))
    def test_audit_events_platform_scoped_action_with_org_is_rejected(self, value: str) -> None:
        """A platform-scoped action must not carry an org_id (org.purge outlives the org)."""
        with pytest.raises(ValidationError):
            _event(
                action=value,
                actor_kind="super_admin",
                actor_user_id=_SUPER_ADMIN,
                org_id=_ORG,
                target_type=None,
                target_ids=(),
            )

    @pytest.mark.parametrize("value", sorted(_PLATFORM_SCOPED))
    def test_audit_events_platform_scoped_action_without_org_is_valid(self, value: str) -> None:
        """A platform-scoped action by a Super Admin with no org_id is valid."""
        event = _event(
            action=value,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_type=None,
            target_ids=(),
        )

        assert event.org_id is None

    @pytest.mark.parametrize("value", sorted(_PLATFORM_SCOPED))
    def test_audit_events_platform_scoped_action_by_system_is_valid(self, value: str) -> None:
        """A platform-scoped action by the system (e.g. the retention purge) is valid."""
        event = _event(
            action=value,
            actor_kind="system",
            actor_user_id=None,
            org_id=None,
            target_type=None,
            target_ids=(),
        )

        assert event.actor_kind == "system"

    @pytest.mark.parametrize("value", sorted(_ANY_SCOPED))
    def test_audit_events_any_scoped_action_accepts_an_org(self, value: str) -> None:
        """A member's login or account-lifecycle event carries the member's org."""
        event = _event(action=value, target_type=None, target_ids=())

        assert event.org_id == _ORG

    @pytest.mark.parametrize("value", sorted(_ANY_SCOPED))
    def test_audit_events_any_scoped_action_accepts_no_org(self, value: str) -> None:
        """A Super Admin's login or account-lifecycle event has no org."""
        event = _event(
            action=value,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_type=None,
            target_ids=(),
        )

        assert event.org_id is None


# ---------------------------------------------------------------------------
# 3. Actor rules
# ---------------------------------------------------------------------------


class TestActorRules:
    """system/operator actors have no user id; member/super_admin need one; a member an org."""

    @pytest.mark.parametrize("kind", ["system", "operator"])
    def test_audit_events_non_user_actor_with_user_id_is_rejected(self, kind: str) -> None:
        """A system or operator actor can't name a user account."""
        with pytest.raises(ValidationError):
            _event(
                action=AuditAction.LOGIN_FAILURE,
                actor_kind=kind,
                actor_user_id=_USER,
                org_id=None,
                target_type=None,
                target_ids=(),
            )

    @pytest.mark.parametrize("kind", ["system", "operator"])
    @pytest.mark.parametrize("org_id", [None, _ORG], ids=["no-org", "org"])
    def test_audit_events_non_user_actor_without_user_id_is_valid(
        self, kind: str, org_id: UUID | None
    ) -> None:
        """A system or operator actor without a user id is valid, with or without an org."""
        event = _event(
            action=AuditAction.LOGIN_LOCKOUT,
            actor_kind=kind,
            actor_user_id=None,
            org_id=org_id,
            target_type=None,
            target_ids=(),
        )

        assert event.actor_user_id is None

    @pytest.mark.parametrize("kind", ["member", "super_admin"])
    def test_audit_events_user_actor_without_user_id_is_rejected(self, kind: str) -> None:
        """A member or Super Admin actor must name the acting user account."""
        with pytest.raises(ValidationError):
            _event(
                action=AuditAction.LOGIN_SUCCESS,
                actor_kind=kind,
                actor_user_id=None,
                org_id=_ORG,
                target_type=None,
                target_ids=(),
            )

    def test_audit_events_member_without_org_is_rejected(self) -> None:
        """A member always acts inside their org, even for an 'any'-scoped action."""
        with pytest.raises(ValidationError):
            _event(
                action=AuditAction.LOGIN_SUCCESS,
                actor_kind="member",
                actor_user_id=_USER,
                org_id=None,
                target_type=None,
                target_ids=(),
            )

    def test_audit_events_super_admin_without_org_is_valid(self) -> None:
        """A Super Admin's login has no org."""
        event = _event(
            action=AuditAction.LOGIN_SUCCESS,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_type=None,
            target_ids=(),
        )

        assert event.actor_user_id == _SUPER_ADMIN

    @pytest.mark.parametrize("kind", ["admin", "root", "Member", "SYSTEM", "org_admin", ""])
    def test_audit_events_unknown_actor_kind_is_rejected(self, kind: str) -> None:
        """actor_kind is one of the four ActorKind values."""
        with pytest.raises(ValidationError):
            _event(actor_kind=kind)

    @pytest.mark.parametrize("user_id", ["alice", "alice@example.com", "Alice Smith", 42])
    def test_audit_events_non_uuid_actor_user_id_is_rejected(self, user_id: object) -> None:
        """actor_user_id is a UUID, never a user name or email."""
        with pytest.raises(ValidationError):
            _event(actor_user_id=user_id)

    @pytest.mark.parametrize("org_id", ["Acme Corp", "acme", 7])
    def test_audit_events_non_uuid_org_id_is_rejected(self, org_id: object) -> None:
        """org_id is a UUID, never an org name."""
        with pytest.raises(ValidationError):
            _event(org_id=org_id)


# ---------------------------------------------------------------------------
# 4. Targets
# ---------------------------------------------------------------------------


class TestTargets:
    """target_type and target_ids come together, and targets are UUIDs only."""

    def test_audit_events_target_ids_without_type_is_rejected(self) -> None:
        """Target IDs need a target type."""
        with pytest.raises(ValidationError):
            _event(target_type=None, target_ids=(_PROJECT,))

    def test_audit_events_target_type_without_ids_is_rejected(self) -> None:
        """A target type needs at least one target ID."""
        with pytest.raises(ValidationError):
            _event(target_type=TargetType.PROJECT, target_ids=())

    def test_audit_events_no_target_is_valid(self) -> None:
        """No target type and no target IDs is a valid event (e.g. a login)."""
        event = _event(target_type=None, target_ids=())

        assert event.target_type is None
        assert event.target_ids == ()

    def test_audit_events_target_ids_default_to_empty(self) -> None:
        """target_type and target_ids default to no target."""
        event = AuditEvent(
            org_id=None,
            actor_kind="system",
            actor_user_id=None,
            action=AuditAction.AUDIT_PURGE,
            metadata={},
        )

        assert event.target_type is None
        assert event.target_ids == ()

    def test_audit_events_target_ids_list_is_stored_as_uuid_tuple(self) -> None:
        """A list of UUIDs is accepted and kept in order as a tuple of UUIDs."""
        event = _event(target_type=TargetType.FILE, target_ids=[_FILE, _PROJECT])

        assert event.target_ids == (_FILE, _PROJECT)
        assert all(isinstance(target, UUID) for target in event.target_ids)

    def test_audit_events_target_type_accepts_its_string_value(self) -> None:
        """target_type accepts the enum's string value."""
        event = _event(target_type="chat")

        assert event.target_type == TargetType.CHAT

    @pytest.mark.parametrize(
        "target",
        ["Project Alpha", "report.pdf", "alice@example.com", "", 42, 1.5, b"Project Alpha!!!"],
        ids=["title", "file-name", "email", "empty", "int", "float", "sixteen-bytes-of-text"],
    )
    def test_audit_events_non_uuid_target_is_rejected(self, target: object) -> None:
        """Target IDs are UUIDs only: no titles, file names or emails, and no 16 bytes of
        text that lax parsing would turn into a UUID carrying the text."""
        with pytest.raises(ValidationError):
            _event(target_ids=(target,))

    @pytest.mark.parametrize("target_type", ["document", "Project", "email", ""])
    def test_audit_events_unknown_target_type_is_rejected(self, target_type: str) -> None:
        """target_type is one of the TargetType values."""
        with pytest.raises(ValidationError):
            _event(target_type=target_type)

    def test_audit_events_one_hundred_targets_are_accepted(self) -> None:
        """Up to 100 target IDs are accepted."""
        targets = tuple(UUID(int=n + 1) for n in range(100))

        assert len(_event(target_ids=targets).target_ids) == 100

    def test_audit_events_more_than_one_hundred_targets_are_rejected(self) -> None:
        """More than 100 target IDs are rejected."""
        targets = tuple(UUID(int=n + 1) for n in range(101))

        with pytest.raises(ValidationError):
            _event(target_ids=targets)


# ---------------------------------------------------------------------------
# 5. IP address (best effort: a non-IP peer becomes None)
# ---------------------------------------------------------------------------


class TestIp:
    """ip accepts IP objects and strings, normalizes them, and drops non-addresses."""

    def test_audit_events_ip_defaults_to_none(self) -> None:
        """An event without an ip has ip None."""
        assert _event().ip is None

    def test_audit_events_ip_none_stays_none(self) -> None:
        """ip=None stays None."""
        assert _event(ip=None).ip is None

    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            pytest.param(IPv4Address(_IP), _IP, id="ipv4-object"),
            pytest.param(IPv6Address("2001:db8::1"), "2001:db8::1", id="ipv6-object"),
            pytest.param(_IP, _IP, id="ipv4-string"),
            pytest.param("2001:db8::1", "2001:db8::1", id="ipv6-string"),
            pytest.param(
                "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", id="ipv6-long-form"
            ),
            pytest.param("::1", "::1", id="ipv6-loopback"),
            pytest.param("127.0.0.1", "127.0.0.1", id="ipv4-loopback"),
        ],
    )
    def test_audit_events_ip_is_normalized(self, given: object, expected: str) -> None:
        """A valid IP (object or string) is stored in its normalized form."""
        event = _event(ip=given)

        assert event.ip is not None
        assert str(event.ip) == expected

    @pytest.mark.parametrize(
        "peer",
        [
            "testclient",
            "",
            "unix-socket",
            "not an ip",
            "999.1.1.1",
            "alice@example.com",
            "localhost",
        ],
    )
    def test_audit_events_non_ip_string_becomes_none(self, peer: str) -> None:
        """A peer string that isn't an IP address (Starlette's 'testclient', a socket name)
        becomes None instead of failing the audit write or storing text."""
        assert _event(ip=peer).ip is None


# ---------------------------------------------------------------------------
# 6. The metadata content validator
# ---------------------------------------------------------------------------


class TestMetadataVocabulary:
    """METADATA_VOCABULARY is the closed set of allowed string values."""

    def test_audit_events_vocabulary_is_a_frozenset(self) -> None:
        """The vocabulary can't be changed at runtime."""
        assert isinstance(METADATA_VOCABULARY, frozenset)

    def test_audit_events_vocabulary_is_exactly_roles_decisions_tools_and_actions(self) -> None:
        """Member roles, permission decisions, and every tool name and tool action of the
        permission engine: nothing else."""
        tools = set(DEFAULT_PERMISSIONS) | {tool for tool, _ in HARDCODED_DENIALS}
        actions = {action for per_tool in DEFAULT_PERMISSIONS.values() for action in per_tool}
        actions |= {action for _, action in HARDCODED_DENIALS}
        expected = {"org_admin", "editor", "viewer", "allow", "confirm", "deny"} | tools | actions

        assert expected == METADATA_VOCABULARY

    @pytest.mark.parametrize("token", ["documents", "download", "store", "recall", "send"])
    def test_audit_events_vocabulary_includes_permission_engine_tokens(self, token: str) -> None:
        """Tokens that only the hardcoded denials or one tool use are included too."""
        assert token in METADATA_VOCABULARY

    def test_audit_events_vocabulary_tokens_are_lowercase_snake_case(self) -> None:
        """Every token matches ^[a-z][a-z0-9_]*$ and is at most 64 characters."""
        assert all(re.fullmatch(r"[a-z][a-z0-9_]*", token) for token in METADATA_VOCABULARY)
        assert all(len(token) <= 64 for token in METADATA_VOCABULARY)

    @pytest.mark.parametrize("word", ["alice", "bob", "secret", "report", "title", "name"])
    def test_audit_events_vocabulary_has_no_names_or_content_words(self, word: str) -> None:
        """Personal names and content words are not in the vocabulary."""
        assert word not in METADATA_VOCABULARY


class TestMetadataValidator:
    """metadata holds non-content details only: the validator rejects free text."""

    @pytest.mark.parametrize("value", _ACCEPTED_VALUES)
    def test_audit_events_metadata_accepts_non_content_value(self, value: object) -> None:
        """Vocabulary tokens, bools, safe-range ints and None are kept unchanged."""
        event = _event(metadata={"value": value})

        assert event.metadata == {"value": value}
        assert type(event.metadata["value"]) is type(value)

    @pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
    def test_audit_events_metadata_bool_stays_bool(self, value: bool) -> None:
        """A bool is kept as a bool, not turned into an int."""
        assert _event(metadata={"residency": value}).metadata["residency"] is value

    def test_audit_events_metadata_uuid_is_stored_as_canonical_string(self) -> None:
        """A UUID object is stored as its canonical lowercase string (JSON-ready)."""
        event = _event(metadata={"project_id": _MARKER})

        assert event.metadata == {"project_id": str(_MARKER)}

    def test_audit_events_metadata_role_change_example_is_valid(self) -> None:
        """The issue's example: old and new role of a role change."""
        event = _event(
            action=AuditAction.USER_ROLE_CHANGE,
            target_type=TargetType.USER,
            target_ids=(_USER,),
            metadata={"old_role": "editor", "new_role": "org_admin"},
        )

        assert event.metadata == {"old_role": "editor", "new_role": "org_admin"}

    def test_audit_events_metadata_tool_call_example_is_valid(self) -> None:
        """A tool call's tool, action and permission decision are all vocabulary tokens."""
        event = _event(
            action=AuditAction.TOOL_CALL,
            target_type=None,
            target_ids=(),
            metadata={"tool": "gmail", "tool_action": "read", "decision": "allow", "count": 3},
        )

        assert event.metadata["tool"] == "gmail"

    def test_audit_events_metadata_none_becomes_empty(self) -> None:
        """metadata=None is stored as an empty dict."""
        assert _event(metadata=None).metadata == {}

    def test_audit_events_metadata_empty_stays_empty(self) -> None:
        """metadata={} is stored as an empty dict."""
        assert _event(metadata={}).metadata == {}

    @pytest.mark.parametrize("value", _REJECTED_VALUES)
    def test_audit_events_metadata_rejects_content_value(self, value: object) -> None:
        """Free text, names, titles, file names, emails, lookalikes, UUID strings, floats,
        decimals, containers, bytes, dates and out-of-range ints are rejected."""
        with pytest.raises(ValidationError):
            _event(metadata={"value": value})

    @pytest.mark.parametrize("key", _ACCEPTED_KEYS)
    def test_audit_events_metadata_accepts_key(self, key: str) -> None:
        """Keys match ^[a-z][a-z0-9_]{0,39}$."""
        assert key in _event(metadata={key: True}).metadata

    @pytest.mark.parametrize("key", _REJECTED_KEYS)
    def test_audit_events_metadata_rejects_key(self, key: str) -> None:
        """Keys that aren't short lowercase snake case are rejected (they could carry text)."""
        with pytest.raises(ValidationError):
            _event(metadata={key: True})

    def test_audit_events_metadata_sixteen_keys_are_accepted(self) -> None:
        """Up to 16 keys are accepted."""
        metadata = {f"k{n}": n for n in range(16)}

        assert _event(metadata=metadata).metadata == metadata

    def test_audit_events_metadata_seventeen_keys_are_rejected(self) -> None:
        """More than 16 keys are rejected."""
        with pytest.raises(ValidationError):
            _event(metadata={f"k{n}": n for n in range(17)})

    @pytest.mark.parametrize("metadata", _NON_MAPPING_METADATA)
    def test_audit_events_metadata_must_be_a_mapping(self, metadata: object) -> None:
        """metadata is a flat mapping, not a string, list or number."""
        with pytest.raises(ValidationError):
            _event(metadata=metadata)

    def test_audit_events_metadata_one_bad_value_rejects_the_event(self) -> None:
        """One content value among valid ones still rejects the whole event."""
        with pytest.raises(ValidationError):
            _event(metadata={"old_role": "editor", "new_role": "viewer", "note": "Bob asked"})


# ---------------------------------------------------------------------------
# 7. AuditEvent is sealed
# ---------------------------------------------------------------------------


class TestAuditEventSealed:
    """AuditEvent only exists through validation and can't change after it."""

    def test_audit_events_event_is_a_sealed_model(self) -> None:
        """AuditEvent builds on access.SealedModel."""
        assert issubclass(AuditEvent, SealedModel)

    def test_audit_events_model_construct_is_refused(self) -> None:
        """model_construct() would skip the content validator, so it raises."""
        with pytest.raises(TypeError):
            AuditEvent.model_construct(
                org_id=_ORG,
                actor_kind="member",
                actor_user_id=_USER,
                action=AuditAction.PROJECT_DELETE,
                metadata={"note": "Quarterly report"},
            )

    def test_audit_events_model_copy_with_update_is_refused(self) -> None:
        """model_copy(update=...) would skip validation, so it raises."""
        with pytest.raises(TypeError):
            _event().model_copy(update={"metadata": {"note": "Quarterly report"}})

    def test_audit_events_event_is_frozen(self) -> None:
        """Fields can't be reassigned after validation."""
        event = _event()

        with pytest.raises(ValidationError):
            event.org_id = _OTHER_ORG

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("title", "Quarterly report"),
            ("email", "alice@example.com"),
            ("file_name", "report.pdf"),
            ("occurred_at", datetime(2020, 1, 1, tzinfo=UTC)),
            ("id", _MARKER),
        ],
    )
    def test_audit_events_extra_field_is_rejected(self, field: str, value: object) -> None:
        """No extra fields: no title, email or file name, and no id or occurred_at (the
        database sets those; the app can't backdate an event)."""
        with pytest.raises(ValidationError):
            _event(**{field: value})


# ---------------------------------------------------------------------------
# 8. record(): one parameterized INSERT
# ---------------------------------------------------------------------------

_EVENT_COLUMNS: frozenset[str] = frozenset(
    {
        "org_id",
        "actor_user_id",
        "actor_kind",
        "action",
        "target_type",
        "target_ids",
        "ip",
        "metadata",
    }
)


class TestRecordInsert:
    """record() writes the validated event with a single parameterized INSERT."""

    async def test_audit_events_record_issues_exactly_one_execute(self, conn: MagicMock) -> None:
        """One event, one statement, no reads."""
        await _record(conn)

        assert conn.execute.await_count == 1
        conn.fetch.assert_not_awaited()
        conn.fetchrow.assert_not_awaited()
        conn.fetchval.assert_not_awaited()
        conn.executemany.assert_not_awaited()

    async def test_audit_events_record_returns_none(self, conn: MagicMock) -> None:
        """record() returns None on success."""
        assert await record(conn, **_record_kwargs()) is None

    async def test_audit_events_record_inserts_into_audit_events(self, conn: MagicMock) -> None:
        """The statement is INSERT INTO audit_events (...) VALUES (...)."""
        await _record(conn)

        sql, _, _, _ = _insert_call(conn)
        assert sql.startswith("insert into audit_events")

    async def test_audit_events_record_writes_exactly_the_event_columns(
        self, conn: MagicMock
    ) -> None:
        """The column list is exactly the event's columns: never id or occurred_at, whose
        database defaults the app can't override (no backdating)."""
        await _record(conn)

        _, columns, _, _ = _insert_call(conn)
        assert sorted(columns) == sorted(_EVENT_COLUMNS)

    async def test_audit_events_record_values_are_only_placeholders(self, conn: MagicMock) -> None:
        """Every VALUES item is a $n placeholder (optionally cast), numbered 1..n, and there
        is exactly one bind argument per placeholder."""
        await _record(conn)

        _, _, values, args = _insert_call(conn)
        numbers = []
        for value in values:
            placeholder = _PLACEHOLDER_RE.fullmatch(value)
            assert placeholder is not None, value
            numbers.append(int(placeholder.group(1)))
        assert sorted(numbers) == list(range(1, len(values) + 1))
        assert len(args) == len(values)

    async def test_audit_events_record_sql_text_contains_no_values(self, conn: MagicMock) -> None:
        """No ID, IP or metadata value is interpolated into the SQL text."""
        await _record(conn, metadata={"role": "editor", "project_id": _MARKER, "count": 31337})

        sql, _, _, _ = _insert_call(conn)
        _assert_no_content(sql, _ORG, _USER, _PROJECT, _MARKER, _IP, "editor", "31337")

    async def test_audit_events_record_sql_is_the_same_for_every_event(
        self, conn: MagicMock
    ) -> None:
        """The statement text is constant: two different events produce the same SQL."""
        other = MagicMock(spec=asyncpg.Connection)
        other.execute = AsyncMock(return_value="INSERT 0 1")

        await _record(conn)
        await _record(
            other,
            action=AuditAction.AUDIT_PURGE,
            actor_kind="system",
            actor_user_id=None,
            org_id=None,
            target_type=None,
            target_ids=(),
            ip=None,
            metadata={"purged_count": 3},
        )

        assert conn.execute.await_args is not None
        assert other.execute.await_args is not None
        assert conn.execute.await_args.args[0] == other.execute.await_args.args[0]

    async def test_audit_events_record_binds_org_and_actor(self, conn: MagicMock) -> None:
        """org_id and actor_user_id bind as UUIDs, actor_kind as its string."""
        await _record(conn)

        row = _inserted_row(conn)
        assert row["org_id"] == _ORG
        assert row["actor_user_id"] == _USER
        assert row["actor_kind"] == "member"

    async def test_audit_events_record_binds_action_value(self, conn: MagicMock) -> None:
        """action binds as its string value."""
        await _record(conn, action=AuditAction.PROJECT_RESTORE)

        row = _inserted_row(conn)
        assert isinstance(row["action"], str)
        assert row["action"] == "project.restore"

    async def test_audit_events_record_binds_targets_as_json_list(self, conn: MagicMock) -> None:
        """target_type binds as its string; target_ids as a JSON list of canonical UUIDs."""
        await _record(conn, target_type=TargetType.FILE, target_ids=[_FILE, _PROJECT])

        row = _inserted_row(conn)
        assert row["target_type"] == "file"
        assert isinstance(row["target_ids"], str)
        assert json.loads(row["target_ids"]) == [str(_FILE), str(_PROJECT)]

    async def test_audit_events_record_binds_ip(self, conn: MagicMock) -> None:
        """ip binds as the normalized address."""
        await _record(conn, ip="2001:0db8:0000:0000:0000:0000:0000:0001")

        assert str(_inserted_row(conn)["ip"]) == "2001:db8::1"

    async def test_audit_events_record_binds_non_ip_peer_as_null(self, conn: MagicMock) -> None:
        """A peer that isn't an IP address ('testclient') binds as NULL."""
        await _record(conn, ip="testclient")

        assert _inserted_row(conn)["ip"] is None

    async def test_audit_events_record_binds_metadata_as_json_object(self, conn: MagicMock) -> None:
        """metadata binds as a JSON string of the validated dict."""
        await _record(conn, metadata={"old_role": "editor", "new_role": "viewer", "seats": 5})

        row = _inserted_row(conn)
        assert isinstance(row["metadata"], str)
        assert json.loads(row["metadata"]) == {
            "old_role": "editor",
            "new_role": "viewer",
            "seats": 5,
        }

    async def test_audit_events_record_binds_uuid_metadata_as_canonical_string(
        self, conn: MagicMock
    ) -> None:
        """A UUID metadata value is written as its canonical string."""
        await _record(conn, metadata={"project_id": _MARKER})

        assert json.loads(_inserted_row(conn)["metadata"]) == {"project_id": str(_MARKER)}

    async def test_audit_events_record_defaults_bind_empty_json_and_nulls(
        self, conn: MagicMock
    ) -> None:
        """Without target, ip or metadata: target_type and ip bind NULL, target_ids '[]',
        metadata '{}'."""
        await record(
            conn,
            action=AuditAction.LOGIN_SUCCESS,
            actor_kind="member",
            actor_user_id=_USER,
            org_id=_ORG,
        )

        row = _inserted_row(conn)
        assert row["target_type"] is None
        assert json.loads(row["target_ids"]) == []
        assert row["ip"] is None
        assert json.loads(row["metadata"]) == {}

    async def test_audit_events_record_accepts_a_pool(self) -> None:
        """A pool works as the executor too (for events outside a caller's transaction)."""
        pool = MagicMock(spec=asyncpg.Pool)
        pool.execute = AsyncMock(return_value="INSERT 0 1")

        await _record(pool)

        assert _inserted_row(pool)["org_id"] == _ORG

    @pytest.mark.parametrize("action", _SUPER_ADMIN_ORG_ACTIONS)
    async def test_audit_events_record_super_admin_org_action_stores_org_id(
        self, conn: MagicMock, action: AuditAction
    ) -> None:
        """A Super Admin action affecting an org is stored with that org's id, so the org's
        admins see it in their audit log."""
        await _record(
            conn,
            action=action,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=_ORG,
            target_type=TargetType.ORGANIZATION,
            target_ids=[_ORG],
            metadata={},
        )

        row = _inserted_row(conn)
        assert row["org_id"] == _ORG
        assert row["actor_kind"] == "super_admin"
        assert row["actor_user_id"] == _SUPER_ADMIN

    async def test_audit_events_record_residency_change_example(self, conn: MagicMock) -> None:
        """The spec's example: a residency change by a Super Admin lands in the org's log."""
        await _record(
            conn,
            action=AuditAction.ORG_RESIDENCY_CHANGE,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=_ORG,
            target_type=TargetType.ORGANIZATION,
            target_ids=[_ORG],
            metadata={"residency": False},
        )

        row = _inserted_row(conn)
        assert row["org_id"] == _ORG
        assert row["action"] == "org.residency_change"
        assert json.loads(row["metadata"]) == {"residency": False}

    async def test_audit_events_record_super_admin_org_action_without_org_fails(
        self, conn: MagicMock
    ) -> None:
        """The same residency change without the org_id is refused before any SQL."""
        with pytest.raises(AuditRecordError):
            await _record(
                conn,
                action=AuditAction.ORG_RESIDENCY_CHANGE,
                actor_kind="super_admin",
                actor_user_id=_SUPER_ADMIN,
                org_id=None,
                target_type=TargetType.ORGANIZATION,
                target_ids=[_ORG],
                metadata={"residency": False},
            )

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_org_purge_is_a_platform_event(self, conn: MagicMock) -> None:
        """org.purge is stored without an org_id (it outlives the org); the org is the target."""
        await _record(
            conn,
            action=AuditAction.ORG_PURGE,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_type=TargetType.ORGANIZATION,
            target_ids=[_ORG],
            metadata={},
        )

        row = _inserted_row(conn)
        assert row["org_id"] is None
        assert json.loads(row["target_ids"]) == [str(_ORG)]


class TestRecordSignature:
    """Callers must decide the org scope and actor explicitly: no defaults."""

    @pytest.mark.parametrize("name", ["action", "actor_kind", "actor_user_id", "org_id"])
    def test_audit_events_record_argument_is_required_keyword_only(self, name: str) -> None:
        """action, actor_kind, actor_user_id and org_id are keyword-only without defaults."""
        parameter = inspect.signature(record).parameters[name]

        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    @pytest.mark.parametrize("name", ["action", "actor_kind", "actor_user_id", "org_id"])
    async def test_audit_events_record_missing_argument_raises_type_error(
        self, conn: MagicMock, name: str
    ) -> None:
        """Leaving out a required argument (e.g. org_id) raises TypeError; nothing is written."""
        kwargs = _record_kwargs()
        del kwargs[name]

        with pytest.raises(TypeError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_rejects_positional_event_arguments(
        self, conn: MagicMock
    ) -> None:
        """Only the executor is positional."""
        record_any: Any = record

        with pytest.raises(TypeError):
            await record_any(conn, AuditAction.LOGIN_SUCCESS, "member", _USER, _ORG)

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("name", ["title", "details", "email", "occurred_at"])
    async def test_audit_events_record_rejects_unknown_keyword(
        self, conn: MagicMock, name: str
    ) -> None:
        """No free-text side channel (title, details, email) and no backdating (occurred_at)."""
        with pytest.raises(TypeError):
            await record(conn, **_record_kwargs(), **{name: "Quarterly report"})

        conn.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# 9. record(): validation failures raise AuditRecordError, before any SQL
# ---------------------------------------------------------------------------

_INVALID_RECORDS: list[Any] = [
    pytest.param({"metadata": {"note": "Quarterly report"}}, id="free-text-metadata"),
    pytest.param({"metadata": {"email": "alice@example.com"}}, id="email-metadata"),
    pytest.param({"metadata": {"file": "report.pdf"}}, id="file-name-metadata"),
    pytest.param({"metadata": {"ratio": 0.5}}, id="float-metadata"),
    pytest.param({"target_ids": ["Project Alpha"]}, id="title-as-target"),
    pytest.param({"target_type": None}, id="targets-without-type"),
    pytest.param({"actor_kind": "system"}, id="system-actor-with-user-id"),
    pytest.param(
        {
            "action": AuditAction.LOGIN_SUCCESS,
            "org_id": None,
            "target_type": None,
            "target_ids": [],
        },
        id="member-without-org",
    ),
    pytest.param({"org_id": None}, id="org-scoped-action-without-org"),
    pytest.param({"action": "user.impersonate"}, id="unknown-action"),
    pytest.param({"actor_kind": "root"}, id="unknown-actor-kind"),
]


class TestRecordValidationFailure:
    """An invalid event raises AuditRecordError and writes nothing."""

    def test_audit_events_record_error_is_a_plain_exception(self) -> None:
        """AuditRecordError is an Exception, not a ValidationError that would echo input."""
        assert issubclass(AuditRecordError, Exception)
        assert not issubclass(AuditRecordError, ValidationError)

    @pytest.mark.parametrize("overrides", _INVALID_RECORDS)
    async def test_audit_events_record_invalid_event_raises_record_error(
        self, conn: MagicMock, overrides: dict[str, Any]
    ) -> None:
        """Invalid input raises AuditRecordError."""
        with pytest.raises(AuditRecordError):
            await _record(conn, **overrides)

    @pytest.mark.parametrize("overrides", _INVALID_RECORDS)
    async def test_audit_events_record_invalid_event_issues_no_sql(
        self, conn: MagicMock, overrides: dict[str, Any]
    ) -> None:
        """Nothing is written for an invalid event."""
        with pytest.raises(AuditRecordError):
            await _record(conn, **overrides)

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("overrides", _INVALID_RECORDS)
    async def test_audit_events_record_invalid_event_error_is_raised_from_none(
        self, conn: MagicMock, overrides: dict[str, Any]
    ) -> None:
        """The Pydantic error (which echoes the input) doesn't travel with it."""
        with pytest.raises(AuditRecordError) as exc_info:
            await _record(conn, **overrides)

        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True


# ---------------------------------------------------------------------------
# 10. record(): write failures raise AuditRecordError (the action aborts)
# ---------------------------------------------------------------------------


class TestRecordFailureAborts:
    """A failed audit write is never swallowed: it aborts the caller's action."""

    @pytest.mark.parametrize("make_error", _db_error_factories())
    async def test_audit_events_record_write_failure_raises_record_error(
        self, conn: MagicMock, make_error: Callable[[], BaseException]
    ) -> None:
        """Database, connection and timeout errors surface as AuditRecordError."""
        conn.execute.side_effect = make_error()

        with pytest.raises(AuditRecordError):
            await _record(conn)

    @pytest.mark.parametrize("make_error", _db_error_factories())
    async def test_audit_events_record_write_failure_is_raised_from_none(
        self, conn: MagicMock, make_error: Callable[[], BaseException]
    ) -> None:
        """The driver error (whose text echoes the row) isn't chained to AuditRecordError."""
        conn.execute.side_effect = make_error()

        with pytest.raises(AuditRecordError) as exc_info:
            await _record(conn)

        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True

    async def test_audit_events_record_unexpected_error_is_not_swallowed(
        self, conn: MagicMock
    ) -> None:
        """Even an unexpected error propagates: record() never reports success after a
        failed write."""
        conn.execute.side_effect = RuntimeError("unexpected")

        with pytest.raises((AuditRecordError, RuntimeError)):
            await _record(conn)

    async def test_audit_events_record_failure_inside_transaction_rolls_back(
        self, conn: MagicMock
    ) -> None:
        """Used inside the caller's transaction, a failed record propagates out of the
        transaction block: __aexit__ sees the error (rollback) and the action's remaining
        steps never run."""
        txn = _transaction(conn)
        conn.execute.side_effect = [
            "UPDATE 1",
            asyncpg.exceptions.CheckViolationError(_failing_row_message()),
        ]
        steps: list[str] = []

        with pytest.raises(AuditRecordError):
            async with conn.transaction():
                await conn.execute("UPDATE users SET role = $1 WHERE id = $2", "viewer", _USER)
                steps.append("role changed")
                await _record(
                    conn,
                    action=AuditAction.USER_ROLE_CHANGE,
                    target_type=TargetType.USER,
                    target_ids=[_USER],
                    metadata={"old_role": "editor", "new_role": "viewer"},
                )
                steps.append("after record")

        assert steps == ["role changed"]
        assert txn.__aexit__.await_args is not None
        exc_type = txn.__aexit__.await_args.args[0]
        assert exc_type is not None
        assert issubclass(exc_type, AuditRecordError)


# ---------------------------------------------------------------------------
# 11. No content in AuditRecordError or in record()'s logs
# ---------------------------------------------------------------------------


class TestAuditRecordErrorCarriesNoContent:
    """AuditRecordError messages and record()'s log lines carry no IDs or input values."""

    @pytest.mark.parametrize(
        ("overrides", "leaked"),
        [
            pytest.param(
                {"metadata": {"note": "Quarterly report"}}, "Quarterly report", id="free-text"
            ),
            pytest.param(
                {"metadata": {"email": "alice@example.com"}}, "alice@example.com", id="email"
            ),
            pytest.param({"metadata": {"file": "report.pdf"}}, "report.pdf", id="file-name"),
            pytest.param({"target_ids": ["Project Alpha"]}, "Project Alpha", id="title-target"),
            pytest.param({"action": "user.impersonate"}, "user.impersonate", id="unknown-action"),
            pytest.param({"metadata": {"count": 2**60}}, str(2**60), id="huge-int"),
        ],
    )
    async def test_audit_events_validation_error_echoes_no_input(
        self, conn: MagicMock, overrides: dict[str, Any], leaked: str
    ) -> None:
        """A validation failure's message, repr and args contain no input value and no ID."""
        with pytest.raises(AuditRecordError) as exc_info:
            await _record(conn, **overrides)

        error = exc_info.value
        for text in (str(error), repr(error), str(error.args)):
            _assert_no_content(text, leaked, _ORG, _USER, _PROJECT, _IP)

    @pytest.mark.parametrize("make_error", _db_error_factories())
    async def test_audit_events_write_error_echoes_no_row_data(
        self, conn: MagicMock, make_error: Callable[[], BaseException]
    ) -> None:
        """A write failure's message, repr and args contain none of the row's IDs, IP or
        metadata values, even though the driver's error text does."""
        conn.execute.side_effect = make_error()

        with pytest.raises(AuditRecordError) as exc_info:
            await _record(conn, metadata={"project_id": _MARKER, "count": _MARKER_COUNT})

        error = exc_info.value
        for text in (str(error), repr(error), str(error.args)):
            _assert_no_content(text, _ORG, _USER, _PROJECT, _MARKER, _IP, _MARKER_COUNT)

    @pytest.mark.parametrize("make_error", _db_error_factories())
    async def test_audit_events_write_failure_logs_no_row_data(
        self,
        conn: MagicMock,
        make_error: Callable[[], BaseException],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Whatever record() logs on a failed write carries no IDs, IP or metadata values
        (no driver error text or traceback with the failing row)."""
        caplog.set_level(logging.DEBUG)
        conn.execute.side_effect = make_error()

        with pytest.raises(AuditRecordError):
            await _record(conn, metadata={"project_id": _MARKER, "count": _MARKER_COUNT})

        _assert_no_content(caplog.text, _ORG, _USER, _PROJECT, _MARKER, _IP, _MARKER_COUNT)

    async def test_audit_events_validation_failure_logs_no_input(
        self, conn: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Whatever record() logs on a validation failure carries no input value or ID."""
        caplog.set_level(logging.DEBUG)

        with pytest.raises(AuditRecordError):
            await _record(conn, metadata={"note": "Quarterly report", "project_id": _MARKER})

        _assert_no_content(caplog.text, "Quarterly report", _ORG, _USER, _PROJECT, _MARKER, _IP)


# ---------------------------------------------------------------------------
# 12. Retention constants
# ---------------------------------------------------------------------------


class TestRetentionConstants:
    """Retention defaults to 12 months within 6 to 84; the purge runs daily."""

    def test_audit_events_default_retention_is_twelve_months(self) -> None:
        """The default retention is 12 months."""
        assert DEFAULT_RETENTION_MONTHS == 12

    def test_audit_events_retention_bounds_are_six_to_eighty_four_months(self) -> None:
        """Retention is bounded to 6 to 84 months (the Super Admin setting arrives in #160)."""
        assert (MIN_RETENTION_MONTHS, MAX_RETENTION_MONTHS) == (6, 84)

    def test_audit_events_default_retention_is_within_bounds(self) -> None:
        """The default is a valid setting."""
        assert MIN_RETENTION_MONTHS <= DEFAULT_RETENTION_MONTHS <= MAX_RETENTION_MONTHS

    def test_audit_events_purge_interval_is_one_day(self) -> None:
        """The purge job runs daily."""
        assert PURGE_INTERVAL_SECONDS == 86400


# ---------------------------------------------------------------------------
# 13. purge_expired(): the retention purge
# ---------------------------------------------------------------------------

_PURGE_SQL_RE = re.compile(
    r"select purge_audit_events\s*\(\s*\$1(?:\s*::\s*(?:integer|int4|int))?\s*\)"
)


def _purge_sql(conn: MagicMock) -> str:
    """Return the normalized SQL of purge_expired's fetchval."""
    assert conn.fetchval.await_args is not None, "purge_expired issued no fetchval"
    return _normalized(conn.fetchval.await_args.args[0])


class TestPurgeExpired:
    """purge_expired() deletes rows past the retention and records one audit.purge event."""

    @pytest.mark.parametrize(
        "months",
        [5, 85, 0, -1, 999, True, False, 12.0, "12", None],
        ids=["5", "85", "0", "-1", "999", "true", "false", "float", "string", "none"],
    )
    async def test_audit_events_purge_invalid_retention_raises_value_error(
        self, mock_pool: MagicMock, months: object
    ) -> None:
        """A retention that isn't an int in [6, 84] raises ValueError before the pool is used."""
        purge_any: Any = purge_expired

        with pytest.raises(ValueError):
            await purge_any(mock_pool, months)

        mock_pool.acquire.assert_not_called()

    @pytest.mark.parametrize("months", [999, -31])
    async def test_audit_events_purge_invalid_retention_error_does_not_echo_input(
        self, mock_pool: MagicMock, months: int
    ) -> None:
        """The ValueError doesn't echo the rejected value."""
        with pytest.raises(ValueError) as exc_info:
            await purge_expired(mock_pool, months)

        assert str(months) not in str(exc_info.value)

    @pytest.mark.parametrize("months", [6, 12, 37, 84])
    async def test_audit_events_purge_calls_the_purge_function_with_months(
        self, mock_pool: MagicMock, months: int
    ) -> None:
        """Valid retentions run SELECT purge_audit_events($1) with the months bound."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        await purge_expired(mock_pool, months)

        assert _PURGE_SQL_RE.fullmatch(_purge_sql(conn)), _purge_sql(conn)
        assert conn.fetchval.await_args is not None
        assert conn.fetchval.await_args.args[1:] == (months,)

    async def test_audit_events_purge_never_interpolates_months(self, mock_pool: MagicMock) -> None:
        """The months travel as a bind parameter, never in the SQL text."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        await purge_expired(mock_pool, 37)

        assert "37" not in _purge_sql(conn)

    async def test_audit_events_purge_defaults_to_twelve_months(self, mock_pool: MagicMock) -> None:
        """Without a retention the default of 12 months applies."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        await purge_expired(mock_pool)

        assert conn.fetchval.await_args is not None
        assert conn.fetchval.await_args.args[1:] == (12,)

    async def test_audit_events_purge_returns_purged_count(self, mock_pool: MagicMock) -> None:
        """The purged row count is returned."""
        mock_pool._mock_conn.fetchval = AsyncMock(return_value=37)

        assert await purge_expired(mock_pool, 12) == 37

    async def test_audit_events_purge_records_one_purge_event(self, mock_pool: MagicMock) -> None:
        """A purge that removed rows records one system audit.purge event with the retention
        and the count, no org, no actor user and no target."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=37)

        await purge_expired(mock_pool, 24)

        row = _inserted_row(conn)
        assert row["action"] == "audit.purge"
        assert row["actor_kind"] == "system"
        assert row["actor_user_id"] is None
        assert row["org_id"] is None
        assert row["target_type"] is None
        assert json.loads(row["target_ids"]) == []
        assert json.loads(row["metadata"]) == {"retention_months": 24, "purged_count": 37}

    async def test_audit_events_purge_records_on_the_same_connection(
        self, mock_pool: MagicMock
    ) -> None:
        """The audit.purge event is written on the purge's own connection, not the pool."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=3)

        await purge_expired(mock_pool, 12)

        assert conn.execute.await_count == 1
        mock_pool.execute.assert_not_awaited()

    async def test_audit_events_purge_of_nothing_records_nothing(
        self, mock_pool: MagicMock
    ) -> None:
        """A purge that removed no rows writes no audit event and returns 0."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        assert await purge_expired(mock_pool, 12) == 0
        conn.execute.assert_not_awaited()
        mock_pool.execute.assert_not_awaited()

    async def test_audit_events_purge_and_record_share_one_transaction(
        self, mock_pool: MagicMock
    ) -> None:
        """The purge and its audit event run inside one transaction: begin, purge, record,
        end."""
        conn = mock_pool._mock_conn
        events: list[str] = []
        txn = conn.transaction.return_value
        txn.__aenter__.side_effect = lambda *_args: events.append("begin")
        txn.__aexit__.side_effect = lambda *_args: events.append("end")

        async def fake_fetchval(*_args: Any) -> int:
            events.append("purge")
            return 5

        async def fake_execute(*_args: Any) -> str:
            events.append("record")
            return "INSERT 0 1"

        conn.fetchval = AsyncMock(side_effect=fake_fetchval)
        conn.execute = AsyncMock(side_effect=fake_execute)

        await purge_expired(mock_pool, 12)

        assert events == ["begin", "purge", "record", "end"]

    async def test_audit_events_purge_record_failure_rolls_back(self, mock_pool: MagicMock) -> None:
        """If the audit.purge event can't be written, AuditRecordError propagates out of the
        transaction (rollback): the purge doesn't happen silently."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=5)
        conn.execute = AsyncMock(
            side_effect=asyncpg.exceptions.CheckViolationError(_failing_row_message())
        )
        txn = conn.transaction.return_value

        with pytest.raises(AuditRecordError):
            await purge_expired(mock_pool, 12)

        assert txn.__aexit__.await_args is not None
        exc_type = txn.__aexit__.await_args.args[0]
        assert exc_type is not None
        assert issubclass(exc_type, AuditRecordError)


# ---------------------------------------------------------------------------
# 14. run_retention_job(): the daily purge loop
# ---------------------------------------------------------------------------


def _months(value: int = 12) -> AsyncMock:
    """A retention_months callable (GH-160): awaited without arguments, returns value."""
    return AsyncMock(return_value=value)


class TestRetentionJob:
    """run_retention_job() purges now, then once per interval, and survives failures.

    GH-160: the retention is a zero-argument async callable (the stored
    retention.audit_months), awaited before each purge.
    """

    async def test_audit_events_job_purges_then_sleeps_in_a_loop(self) -> None:
        """Purge, sleep, purge, sleep, ... until cancelled."""
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            _patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(3, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_retention_job(MagicMock(), retention_months=_months())

        assert events == ["purge", "sleep", "purge", "sleep", "purge", "sleep"]

    async def test_audit_events_job_first_purge_runs_immediately(self) -> None:
        """The first purge runs before the first sleep."""
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            _patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(1, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_retention_job(MagicMock(), retention_months=_months())

        assert events == ["purge", "sleep"]

    async def test_audit_events_job_defaults_to_a_daily_purge_of_the_callables_months(
        self,
    ) -> None:
        """By default the job purges the given pool with the callable's months (12 here),
        every 86400 seconds."""
        pool = MagicMock()
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(pool, retention_months=_months(12))

        assert [_purge_pool(call) for call in purge.await_args_list] == [pool, pool]
        assert [_purge_months(call) for call in purge.await_args_list] == [12, 12]
        assert [_sleep_delay(call) for call in sleep.await_args_list] == [86400, 86400]

    async def test_audit_events_job_passes_custom_retention_and_interval(self) -> None:
        """The callable's months (24) and interval_seconds are passed through."""
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(1)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=_months(24), interval_seconds=5)

        assert _purge_months(purge.await_args_list[0]) == 24
        assert _sleep_delay(sleep.await_args_list[0]) == 5

    def test_audit_events_job_retention_months_is_a_required_keyword(self) -> None:
        """GH-160: retention_months is keyword-only with no default (the caller passes the
        callable of the stored value)."""
        parameter = inspect.signature(run_retention_job).parameters["retention_months"]

        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    async def test_audit_events_job_awaits_the_retention_before_each_purge(self) -> None:
        """GH-160: every run awaits retention_months() (no arguments) first, then purges
        with its value."""
        events: list[str] = []

        async def months() -> int:
            events.append("months")
            return 36

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        purge = AsyncMock(side_effect=fake_purge)
        with (
            _patched_job(purge, _cancelling_sleep(2, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_retention_job(MagicMock(), retention_months=months)

        assert events == ["months", "purge", "sleep", "months", "purge", "sleep"]
        assert [_purge_months(call) for call in purge.await_args_list] == [36, 36]

    async def test_audit_events_job_uses_a_changed_retention_on_the_next_run(self) -> None:
        """AC (GH-160): the stored value changes between two runs (12 to 60 months): the
        next purge uses the new value, without a restart."""
        stored = {"months": 12}

        async def months() -> int:
            return stored["months"]

        async def changing_sleep(_delay: float) -> None:
            stored["months"] = 60
            if purge.await_count >= 2:
                raise asyncio.CancelledError

        purge = AsyncMock(return_value=0)
        with (
            _patched_job(purge, AsyncMock(side_effect=changing_sleep)),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_retention_job(MagicMock(), retention_months=months)

        assert [_purge_months(call) for call in purge.await_args_list] == [12, 60]

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("boom"), id="runtime-error"),
            pytest.param(lambda: OSError("connection refused"), id="os-error"),
            pytest.param(lambda: asyncpg.exceptions.RaiseError("refused"), id="postgres-error"),
            pytest.param(lambda: ValueError("bad retention"), id="value-error"),
        ],
    )
    async def test_audit_events_job_survives_a_failed_retention_lookup(
        self, make_error: Callable[[], Exception]
    ) -> None:
        """GH-160: a failing retention_months() skips that run's purge; the job sleeps and
        tries again next interval."""
        months = AsyncMock(side_effect=[make_error(), 24])
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=months)

        assert months.await_count == 2
        assert [_purge_months(call) for call in purge.await_args_list] == [24]
        assert [_sleep_delay(call) for call in sleep.await_args_list] == [86400, 86400]

    async def test_audit_events_job_logs_a_failed_retention_lookup_by_class_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """GH-160: the failed lookup is one admino WARNING naming the exception class and
        carrying none of its text."""
        caplog.set_level(logging.DEBUG)
        months = AsyncMock(side_effect=RuntimeError(_failing_row_message()))

        with (
            _patched_job(AsyncMock(return_value=0), _cancelling_sleep(1)),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_retention_job(MagicMock(), retention_months=months)

        warnings = [
            entry
            for entry in caplog.records
            if entry.levelno == logging.WARNING and entry.name.startswith("admino")
        ]
        assert len(warnings) == 1
        assert "RuntimeError" in warnings[0].getMessage()
        _assert_no_content(caplog.text, _ORG, _USER, _PROJECT, _MARKER, _IP, _MARKER_COUNT)

    async def test_audit_events_job_cancelled_retention_lookup_propagates(self) -> None:
        """GH-160: cancellation while awaiting retention_months() stops the job (no purge,
        no sleep)."""
        months = AsyncMock(side_effect=asyncio.CancelledError)
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(5)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=months)

        purge.assert_not_awaited()
        sleep.assert_not_awaited()

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("boom"), id="runtime-error"),
            pytest.param(lambda: OSError("connection refused"), id="os-error"),
            pytest.param(lambda: asyncpg.exceptions.RaiseError("refused"), id="postgres-error"),
            pytest.param(lambda: AuditRecordError("audit write failed"), id="audit-record-error"),
            pytest.param(lambda: ValueError("bad retention"), id="value-error"),
        ],
    )
    async def test_audit_events_job_survives_a_failed_purge(
        self, make_error: Callable[[], Exception]
    ) -> None:
        """A failing purge doesn't stop the job: it sleeps and purges again next interval."""
        purge = AsyncMock(side_effect=[make_error(), 4])
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=_months())

        assert purge.await_count == 2
        assert [_sleep_delay(call) for call in sleep.await_args_list] == [86400, 86400]

    async def test_audit_events_job_logs_a_failed_purge_as_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A failed purge is logged as a warning."""
        caplog.set_level(logging.DEBUG)
        purge = AsyncMock(side_effect=RuntimeError("boom"))

        with _patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=_months())

        assert any(
            entry.levelno == logging.WARNING and entry.name.startswith("admino")
            for entry in caplog.records
        )

    async def test_audit_events_job_failure_log_carries_no_content(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning carries no IDs or values from the failure (no error text, no traceback)."""
        caplog.set_level(logging.DEBUG)
        purge = AsyncMock(side_effect=asyncpg.exceptions.RaiseError(_failing_row_message()))

        with _patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=_months())

        _assert_no_content(caplog.text, _ORG, _USER, _PROJECT, _MARKER, _IP, _MARKER_COUNT)

    async def test_audit_events_job_cancelled_purge_propagates(self) -> None:
        """Cancellation during a purge stops the job (it isn't treated as a failed purge)."""
        purge = AsyncMock(side_effect=asyncio.CancelledError)
        sleep = _cancelling_sleep(5)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await run_retention_job(MagicMock(), retention_months=_months())

        assert purge.await_count == 1
        sleep.assert_not_awaited()

    async def test_audit_events_job_task_cancel_stops_it(self) -> None:
        """Cancelling the job's task while it sleeps ends the task as cancelled."""
        sleeping = asyncio.Event()

        async def blocking_sleep(_delay: float) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        purge = AsyncMock(return_value=0)
        with _patched_job(purge, AsyncMock(side_effect=blocking_sleep)):
            task = asyncio.create_task(run_retention_job(MagicMock(), retention_months=_months()))
            async with asyncio.timeout(5):
                await sleeping.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert task.cancelled()


# ---------------------------------------------------------------------------
# 15. The server lifespan starts and stops the retention job
# ---------------------------------------------------------------------------


def _make_config() -> MagicMock:
    """Build a minimal mock AppConfig for create_app."""
    config = MagicMock()
    config.auth.mode = "token"
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    config.auth.token = SecretStr(_TEST_TOKEN)
    return config


class _JobProbe:
    """Stands in for run_retention_job: records its start, waits forever, notes cancellation."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.pools: list[Any] = []
        self.kwargs: list[dict[str, Any]] = []
        self.tasks: list[asyncio.Task[Any]] = []
        self.pool: Any = MagicMock(name="pool")

    async def job(self, pool: Any, *_args: Any, **kwargs: Any) -> None:
        """The fake job: blocks until cancelled, then finishes after one more loop turn."""
        task = asyncio.current_task()
        assert task is not None
        self.tasks.append(task)
        self.pools.append(pool)
        self.kwargs.append(dict(kwargs))
        self.events.append("job-started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append("job-cancelled")
            await _REAL_SLEEP(0)
            self.events.append("job-finished")
            raise


@contextlib.contextmanager
def _patched_lifespan(probe: _JobProbe) -> Iterator[None]:
    """Patch the lifespan's database calls and the retention job with fakes.

    get_pool() raises until init_pool() ran, like the real one, so the job can
    only start after the pool exists. GH-152's session purge job and GH-154's org
    purge job are stubbed with their own probes, so no real purge runs against the
    MagicMock pool (``create=True``: the jobs are new, and these tests don't depend
    on them).
    """
    state: dict[str, Any] = {"pool": None}
    session_purge = _JobProbe()
    org_purge = _JobProbe()

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
        patch("admino.audit_events.run_retention_job", probe.job),
        patch("admino.sessions.run_session_purge_job", session_purge.job, create=True),
        patch_org_purge_job(org_purge.job),
        # GH-157: the login throttle purge never runs against the MagicMock pool.
        patch_login_throttle_purge_job(AsyncMock()),
    ):
        yield


def _store_audit_months(monkeypatch: pytest.MonkeyPatch, months: int) -> None:
    """Make the cached platform settings carry this audit retention (GH-160).

    Built from a dict at call time: StoredPlatformSettings' retention section is
    new in #160.
    """
    data = default_test_platform_settings().model_dump()
    data["retention"] = {**data.get("retention", {}), "audit_months": months}
    stored = scoped_settings.StoredPlatformSettings.model_validate(data)
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored)


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(5):
        await _REAL_SLEEP(0)


class TestLifespanStartsRetentionJob:
    """The server lifespan runs the daily retention job while the app is up."""

    async def test_audit_events_lifespan_starts_job_with_the_pool(self) -> None:
        """After startup the retention job runs with the pool from get_pool()."""
        probe = _JobProbe()
        app = create_app(agent=MagicMock(), config=_make_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert probe.pools == [probe.pool]

    async def test_audit_events_lifespan_passes_the_stored_audit_months(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GH-160: the job gets retention_months, a zero-argument async callable returning
        the cached retention.audit_months, read on every call (36, then 60 after a
        change) and never through the MagicMock pool."""
        _store_audit_months(monkeypatch, 36)
        probe = _JobProbe()
        app = create_app(agent=MagicMock(), config=_make_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                months = probe.kwargs[0]["retention_months"]
                first = await months()
                _store_audit_months(monkeypatch, 60)
                second = await months()

        assert (first, second) == (36, 60)
        assert probe.pool.mock_calls == []

    async def test_audit_events_lifespan_starts_job_after_init_pool(self) -> None:
        """The job starts only once the pool exists."""
        probe = _JobProbe()
        app = create_app(agent=MagicMock(), config=_make_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "job-started" in probe.events
        assert probe.events.index("init_pool") < probe.events.index("job-started")

    async def test_audit_events_lifespan_cancels_job_on_shutdown(self) -> None:
        """On shutdown the job's task is cancelled."""
        probe = _JobProbe()
        app = create_app(agent=MagicMock(), config=_make_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert len(probe.tasks) == 1
        assert probe.tasks[0].cancelled()

    async def test_audit_events_lifespan_awaits_job_before_closing_pool(self) -> None:
        """The cancelled job is awaited to completion before the pool closes, so it never
        runs against a closed pool."""
        probe = _JobProbe()
        app = create_app(agent=MagicMock(), config=_make_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "job-finished" in probe.events
        assert "close_pool" in probe.events
        assert probe.events.index("job-finished") < probe.events.index("close_pool")


# ---------------------------------------------------------------------------
# 16. Module isolation and hygiene
# ---------------------------------------------------------------------------

_FORBIDDEN_EXACT: tuple[str, ...] = (
    "admino.server",
    "admino.agent",
    "admino.main",
    "admino.audit",
)
_FORBIDDEN_PREFIXES: tuple[str, ...] = ("admino.llm", "admino.tools", "admino.oauth")
_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"asyncpg", "pydantic"})
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


def _is_forbidden(module: str) -> bool:
    """True for server/agent/main/NDJSON-audit modules and the llm*/tools*/oauth* families."""
    if module.startswith(_FORBIDDEN_PREFIXES):
        return True
    return any(module == name or module.startswith(f"{name}.") for name in _FORBIDDEN_EXACT)


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
            and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and _SQL_KEYWORD_RE.search(node.left.value)
        ):
            sites.append(f"line {node.lineno}: %-format")
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


class TestModuleIsolation:
    """audit_events.py stays out of the other layers and builds no SQL from values."""

    def test_audit_events_imports_no_forbidden_modules(self) -> None:
        """No imports from server, agent, main, llm*, tools*, oauth* or the NDJSON audit log."""
        modules = _imported_modules(_SRC_DIR / "audit_events.py")

        assert [module for module in modules if _is_forbidden(module)] == []

    def test_audit_events_permission_engine_does_not_import_it(self) -> None:
        """permissions.py gains no import of audit_events (the engine stays untouched)."""
        modules = _imported_modules(_SRC_DIR / "permissions.py")

        assert [module for module in modules if module.startswith("admino.audit_events")] == []

    def test_audit_events_adds_no_new_dependency(self) -> None:
        """Only the standard library, asyncpg, pydantic and admino itself are imported."""
        roots = {module.split(".")[0] for module in _imported_modules(_SRC_DIR / "audit_events.py")}
        third_party = {
            root for root in roots if root not in sys.stdlib_module_names and root != "admino"
        }

        assert third_party <= _ALLOWED_THIRD_PARTY

    def test_audit_events_builds_no_sql_by_string_formatting(self) -> None:
        """No f-string, %-format or .format() produces SQL: values are bind parameters."""
        assert _formatted_sql_sites(_SRC_DIR / "audit_events.py") == []

    def test_audit_events_makes_no_dynamic_code_calls(self) -> None:
        """No eval, exec, compile or __import__ in audit_events.py."""
        tree = ast.parse((_SRC_DIR / "audit_events.py").read_text(encoding="utf-8"))
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]

        assert calls == []

    def test_audit_events_docstring_describes_append_only_content_free_store(self) -> None:
        """The module docstring documents the append-only, content-free contract."""
        doc = (audit_events_mod.__doc__ or "").lower()

        assert "append-only" in doc or "append only" in doc
        assert "content" in doc


# ---------------------------------------------------------------------------
# GH-147: record_tool_call — the tool.call row the agent's recorder writes.
# GH-149: the row names the acting member (actor_kind member, their user id and
# org) instead of a system actor in the default org.
# ---------------------------------------------------------------------------

_CHAT = UUID("f1e2d3c4-b5a6-4978-8a9b-0c1d2e3f4a5b")


def _record_tool_call() -> Callable[..., Any]:
    """Look record_tool_call up lazily, so the rest of this file collects without it."""
    func = getattr(audit_events_mod, "record_tool_call", None)
    assert func is not None, "admino.audit_events must define record_tool_call"
    return func  # type: ignore[no-any-return]


def _tool_call_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "org_id": _ORG,
        "actor_user_id": _USER,
        "chat_id": _CHAT,
        "tool": "gmail",
        "action": "read",
        "decision": "allow",
        "success": True,
        "duration_ms": 42,
        "escalated": False,
    }
    kwargs.update(overrides)
    return kwargs


class TestRecordToolCall:
    """record_tool_call writes one content-free tool.call row (GH-147)."""

    @pytest.mark.asyncio
    async def test_issues_exactly_one_audit_events_insert(self, conn: MagicMock) -> None:
        await _record_tool_call()(conn, **_tool_call_kwargs())

        sql, _, _, _ = _insert_call(conn)
        assert sql.startswith("insert into audit_events")

    @pytest.mark.asyncio
    async def test_row_is_a_member_tool_call_on_the_chat(self, conn: MagicMock) -> None:
        """GH-149: the acting member, not a system actor: actor_kind member, their user id
        and their org."""
        await _record_tool_call()(conn, **_tool_call_kwargs())

        row = _inserted_row(conn)
        assert row["action"] == "tool.call"
        assert row["actor_kind"] == "member"
        assert row["actor_user_id"] == _USER
        assert row["org_id"] == _ORG
        assert row["target_type"] == "chat"
        assert json.loads(row["target_ids"]) == [str(_CHAT)]
        assert row["ip"] is None

    @pytest.mark.asyncio
    async def test_metadata_is_exactly_the_six_fields(self, conn: MagicMock) -> None:
        await _record_tool_call()(conn, **_tool_call_kwargs())

        metadata = json.loads(_inserted_row(conn)["metadata"])
        assert metadata == {
            "tool": "gmail",
            "action": "read",
            "decision": "allow",
            "success": True,
            "duration_ms": 42,
            "escalated": False,
        }

    @pytest.mark.asyncio
    @pytest.mark.parametrize("decision", ["allow", "confirm", "deny"])
    async def test_every_permission_decision_is_recorded(
        self, conn: MagicMock, decision: str
    ) -> None:
        await _record_tool_call()(conn, **_tool_call_kwargs(decision=decision, success=False))

        metadata = json.loads(_inserted_row(conn)["metadata"])
        assert metadata["decision"] == decision
        assert metadata["success"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool", "action"),
        [
            ("made_up_tool", "read"),
            ("gmail", "exfiltrate_all"),
            ("rm -rf /", "now"),
            ("Please email bob@example.com", "the report.pdf"),
            ("", ""),
            ("invalid", "rejected"),
        ],
    )
    async def test_names_outside_the_vocabulary_become_none(
        self, conn: MagicMock, tool: str, action: str
    ) -> None:
        """A hallucinated or malformed name is never stored as LLM-chosen text."""
        await _record_tool_call()(conn, **_tool_call_kwargs(tool=tool, action=action))

        row = _inserted_row(conn)
        metadata = json.loads(row["metadata"])
        if tool not in METADATA_VOCABULARY:
            assert metadata["tool"] is None
        if action not in METADATA_VOCABULARY:
            assert metadata["action"] is None
        for value in (tool, action):
            if value and value not in METADATA_VOCABULARY:
                assert value not in row["metadata"]

    @pytest.mark.asyncio
    async def test_known_names_are_kept_verbatim(self, conn: MagicMock) -> None:
        await _record_tool_call()(
            conn, **_tool_call_kwargs(tool="google_drive", action="download", decision="confirm")
        )

        metadata = json.loads(_inserted_row(conn)["metadata"])
        assert (metadata["tool"], metadata["action"]) == ("google_drive", "download")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("decision", ["disabled", "allowed", "Allow", "ok, sent it", ""])
    async def test_invalid_decision_raises_and_writes_nothing(
        self, conn: MagicMock, decision: str
    ) -> None:
        with pytest.raises(AuditRecordError):
            await _record_tool_call()(conn, **_tool_call_kwargs(decision=decision))

        conn.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_write_failure_raises_audit_record_error(self, conn: MagicMock) -> None:
        conn.execute.side_effect = OSError("connection reset")

        with pytest.raises(AuditRecordError):
            await _record_tool_call()(conn, **_tool_call_kwargs())

    @pytest.mark.asyncio
    async def test_bind_parameters_only(self, conn: MagicMock) -> None:
        """The org, user and chat IDs travel as bind parameters, never in the SQL text."""
        await _record_tool_call()(conn, **_tool_call_kwargs())

        sql, _, _, _ = _insert_call(conn)
        _assert_no_content(sql, _ORG, _USER, _CHAT)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"actor_user_id": None}, id="no-user"),
            pytest.param({"org_id": None}, id="no-org"),
        ],
    )
    async def test_member_row_without_user_or_org_raises_and_writes_nothing(
        self, conn: MagicMock, overrides: dict[str, Any]
    ) -> None:
        """A member always names their user id and acts inside an org: a missing one is
        refused (AuditRecordError) before anything is written."""
        with pytest.raises(AuditRecordError):
            await _record_tool_call()(conn, **_tool_call_kwargs(**overrides))

        conn.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_member_ids_from_asyncpg_are_stored_as_plain_uuids(self, conn: MagicMock) -> None:
        """IDs read from a users row (asyncpg's UUID subclass) are stored canonically."""
        from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

        await _record_tool_call()(
            conn,
            **_tool_call_kwargs(org_id=PgUUID(str(_ORG)), actor_user_id=PgUUID(str(_USER))),
        )

        row = _inserted_row(conn)
        assert (type(row["org_id"]), type(row["actor_user_id"])) == (UUID, UUID)
        assert (row["org_id"], row["actor_user_id"]) == (_ORG, _USER)

    def test_signature_is_keyword_only_after_the_executor(self) -> None:
        params = list(inspect.signature(_record_tool_call()).parameters.values())

        assert params[0].name == "executor"
        assert {p.name for p in params[1:]} == set(_tool_call_kwargs())
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])


# ---------------------------------------------------------------------------
# GH-161: the org tool permission actions
# ---------------------------------------------------------------------------

# Member name -> value. Looked up at call time: the members are new in GH-161.
_PERMISSION_ACTIONS: dict[str, str] = {
    "ORG_PERMISSION_CHANGE": "org.permission_change",
    "ORG_PERMISSION_PROMOTE": "org.permission_promote",
    "ORG_PERMISSION_PROMOTE_CANCEL": "org.permission_promote_cancel",
    "ORG_PERMISSION_DEMOTE": "org.permission_demote",
}
_PERMISSION_VALUES: list[str] = sorted(_PERMISSION_ACTIONS.values())

# The contract's metadata shape of each action (gmail.send, a promotable pair).
_PERMISSION_METADATA: dict[str, dict[str, Any]] = {
    "org.permission_change": {"tool": "gmail", "action": "send", "old": "deny", "new": "confirm"},
    "org.permission_promote": {"tool": "gmail", "action": "send", "old": "deny", "new": "confirm"},
    "org.permission_demote": {"tool": "gmail", "action": "send", "old": "confirm", "new": "deny"},
    "org.permission_promote_cancel": {"tool": "gmail", "action": "send"},
}

_DEFAULT_PAIRS: list[tuple[str, str]] = sorted(
    (tool, action) for tool, actions in DEFAULT_PERMISSIONS.items() for action in actions
)
_STATE_CHANGES: list[tuple[str, str]] = [
    (old, new)
    for old in ("allow", "confirm", "deny")
    for new in ("allow", "confirm", "deny")
    if old != new
]

# Metadata a permission event must refuse: free text and lookalikes where the
# contract allows tool, action and state tokens only.
_FREE_TEXT_PERMISSION_METADATA: list[Any] = [
    pytest.param(
        {"tool": "Gmail Send", "action": "send", "old": "deny", "new": "confirm"},
        id="tool-free-text",
    ),
    pytest.param(
        {"tool": "slack", "action": "send", "old": "deny", "new": "confirm"},
        id="tool-not-in-vocabulary",
    ),
    pytest.param(
        {"tool": "gmail.send", "action": "send", "old": "deny", "new": "confirm"},
        id="tool-dotted-pair",
    ),
    pytest.param(
        {"tool": "gmail" + _NEWLINE, "action": "send", "old": "deny", "new": "confirm"},
        id="tool-trailing-newline",
    ),
    pytest.param(
        {"tool": "GMAIL", "action": "send", "old": "deny", "new": "confirm"},
        id="tool-upper-case",
    ),
    pytest.param(
        {"tool": b"gmail", "action": "send", "old": "deny", "new": "confirm"},
        id="tool-bytes",
    ),
    pytest.param(
        {"tool": "gmail", "action": "send an email to bob", "old": "deny", "new": "confirm"},
        id="action-free-text",
    ),
    pytest.param(
        {"tool": "gmail", "action": "s" + _CYRILLIC_IE + "nd", "old": "deny", "new": "confirm"},
        id="action-lookalike",
    ),
    pytest.param(
        {"tool": "gmail", "action": "send", "old": "denied", "new": "confirm"},
        id="old-state-not-a-token",
    ),
    pytest.param(
        {"tool": "gmail", "action": "send", "old": "deny", "new": "Confirm"},
        id="new-state-case-variant",
    ),
    pytest.param(
        {"tool": "gmail", "action": "send", "reason": "Bob asked for it"},
        id="free-text-reason",
    ),
    pytest.param(
        {"tool": "gmail", "action": "send", "email": "alice@example.com"},
        id="email",
    ),
]


def _permission_action(value: str) -> AuditAction:
    """The AuditAction for a GH-161 value (raises ValueError until it exists)."""
    return AuditAction(value)


def _permission_record_kwargs(value: str, **overrides: Any) -> dict[str, Any]:
    """record() keyword arguments for a GH-161 row: an Org Admin acting on their org."""
    kwargs: dict[str, Any] = {
        "action": _permission_action(value),
        "actor_kind": "member",
        "actor_user_id": _USER,
        "org_id": _ORG,
        "target_type": TargetType.ORGANIZATION,
        "target_ids": [_ORG],
        "ip": _IP,
        "metadata": _PERMISSION_METADATA[value],
    }
    kwargs.update(overrides)
    return kwargs


class TestOrgPermissionActions:
    """GH-161's four org-scoped actions and their token-only metadata."""

    @pytest.mark.parametrize(("name", "value"), sorted(_PERMISSION_ACTIONS.items()))
    def test_audit_events_permission_action_member_has_contract_value(
        self, name: str, value: str
    ) -> None:
        """AuditAction.ORG_PERMISSION_CHANGE is "org.permission_change", and so on."""
        member = getattr(AuditAction, name)

        assert member.value == value
        assert AuditAction(value) is member

    @pytest.mark.parametrize("value", _PERMISSION_VALUES)
    def test_audit_events_permission_action_is_org_scoped(self, value: str) -> None:
        """Every permission event belongs to the org's log."""
        assert ACTION_SCOPES[_permission_action(value)] == "org"

    @pytest.mark.parametrize("value", _PERMISSION_VALUES)
    async def test_audit_events_record_permission_action_with_org_is_stored(
        self, conn: MagicMock, value: str
    ) -> None:
        """The contract's row: the Org Admin as a member actor, their org, the org as the
        target, the client IP and the token metadata."""
        await record(conn, **_permission_record_kwargs(value))

        row = _inserted_row(conn)
        assert row["action"] == value
        assert row["org_id"] == _ORG
        assert (row["actor_kind"], row["actor_user_id"]) == ("member", _USER)
        assert row["target_type"] == "organization"
        assert json.loads(row["target_ids"]) == [str(_ORG)]
        assert str(row["ip"]) == _IP
        assert json.loads(row["metadata"]) == _PERMISSION_METADATA[value]

    @pytest.mark.parametrize("value", _PERMISSION_VALUES)
    @pytest.mark.parametrize(
        ("actor_kind", "actor_user_id"),
        [
            pytest.param("super_admin", _SUPER_ADMIN, id="super-admin"),
            pytest.param("system", None, id="system"),
        ],
    )
    async def test_audit_events_record_permission_action_without_org_is_refused(
        self, conn: MagicMock, value: str, actor_kind: str, actor_user_id: UUID | None
    ) -> None:
        """Without an org_id the event has no log to land in: refused before any SQL."""
        kwargs = _permission_record_kwargs(
            value, actor_kind=actor_kind, actor_user_id=actor_user_id, org_id=None
        )

        with pytest.raises(AuditRecordError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        ("tool", "action"), [pytest.param(t, a, id=f"{t}.{a}") for t, a in _DEFAULT_PAIRS]
    )
    def test_audit_events_change_metadata_of_every_default_pair_is_valid(
        self, tool: str, action: str
    ) -> None:
        """Every (tool, action) of DEFAULT_PERMISSIONS is a pair of vocabulary tokens."""
        metadata = {"tool": tool, "action": action, "old": "allow", "new": "deny"}

        event = _event(
            action=_permission_action("org.permission_change"),
            target_type=TargetType.ORGANIZATION,
            target_ids=(_ORG,),
            metadata=metadata,
        )

        assert event.metadata == metadata

    @pytest.mark.parametrize(
        ("old", "new"), [pytest.param(o, n, id=f"{o}-to-{n}") for o, n in _STATE_CHANGES]
    )
    def test_audit_events_change_metadata_of_every_state_change_is_valid(
        self, old: str, new: str
    ) -> None:
        metadata = {"tool": "google_calendar", "action": "create", "old": old, "new": new}

        event = _event(
            action=_permission_action("org.permission_change"),
            target_type=TargetType.ORGANIZATION,
            target_ids=(_ORG,),
            metadata=metadata,
        )

        assert event.metadata == metadata

    @pytest.mark.parametrize(
        "value",
        ["org.permission_promote", "org.permission_demote", "org.permission_promote_cancel"],
    )
    @pytest.mark.parametrize(
        ("tool", "action"),
        [pytest.param(t, a, id=f"{t}.{a}") for t, a in sorted(PROMOTABLE_DENIALS)],
    )
    def test_audit_events_critical_metadata_of_every_promotable_pair_is_valid(
        self, value: str, tool: str, action: str
    ) -> None:
        """Promote (deny -> confirm), demote (confirm -> deny) and cancel ({tool, action})
        validate for each of the four promotable denials."""
        metadata = {**_PERMISSION_METADATA[value], "tool": tool, "action": action}

        event = _event(
            action=_permission_action(value),
            target_type=TargetType.ORGANIZATION,
            target_ids=(_ORG,),
            metadata=metadata,
        )

        assert event.metadata == metadata

    @pytest.mark.parametrize("value", _PERMISSION_VALUES)
    @pytest.mark.parametrize("metadata", _FREE_TEXT_PERMISSION_METADATA)
    async def test_audit_events_record_permission_action_free_text_is_refused(
        self, conn: MagicMock, value: str, metadata: dict[str, Any]
    ) -> None:
        """A tool or action name outside the vocabulary, a state that isn't a token or a
        free-text field is refused (AuditRecordError) and nothing is written."""
        kwargs = _permission_record_kwargs(value, metadata=metadata)

        with pytest.raises(AuditRecordError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_permission_action_error_repeats_no_free_text(
        self, conn: MagicMock
    ) -> None:
        """The refusal carries none of the rejected text or the IDs."""
        kwargs = _permission_record_kwargs(
            "org.permission_change",
            metadata={"tool": "Gmail Send", "action": "send", "old": "deny", "new": "confirm"},
        )

        with pytest.raises(AuditRecordError) as caught:
            await record(conn, **kwargs)

        _assert_no_content(str(caught.value), "Gmail Send", _ORG, _USER)
        _assert_no_content(repr(caught.value), "Gmail Send", _ORG, _USER)
        assert caught.value.__cause__ is None


# ---------------------------------------------------------------------------
# GH-164: user.profile_change (an Org Admin changes a user's name or email)
# ---------------------------------------------------------------------------

_PROFILE_CHANGE = "user.profile_change"

# The contract's metadata of a successful change: which of the two fields changed.
_PROFILE_FLAGS: list[Any] = [
    pytest.param(True, False, id="name-only"),
    pytest.param(False, True, id="email-only"),
    pytest.param(True, True, id="name-and-email"),
]

# A name or an address in place of (or next to) the flags: content, always refused.
_PROFILE_CONTENT_METADATA: list[Any] = [
    pytest.param(
        {"name_changed": True, "email_changed": True, "new_email": "ada@example.ch"}, id="new-email"
    ),
    pytest.param(
        {"name_changed": False, "email_changed": True, "old_email": "Ada@Example.CH"},
        id="old-email",
    ),
    pytest.param({"email_changed": "ada.lovelace@example.ch"}, id="email-as-flag-value"),
    pytest.param({"email": "ada@example.ch"}, id="email-key"),
    pytest.param({"email_taken": "ada@example.ch"}, id="email-as-taken-value"),
    pytest.param({"name_changed": True, "new_name": "Ada Lovelace"}, id="new-name"),
    pytest.param({"name_changed": True, "old_name": "Alice"}, id="old-name"),
    pytest.param({"name_changed": "Ada Lovelace"}, id="name-as-flag-value"),
    pytest.param({"name": "ada"}, id="lowercase-name"),
]


def _profile_change() -> AuditAction:
    """The AuditAction for user.profile_change (raises ValueError until it exists)."""
    return AuditAction(_PROFILE_CHANGE)


def _profile_record_kwargs(**overrides: Any) -> dict[str, Any]:
    """record() keyword arguments for the contract's row: an Org Admin changed a user."""
    kwargs: dict[str, Any] = {
        "action": _profile_change(),
        "actor_kind": "member",
        "actor_user_id": _USER,
        "org_id": _ORG,
        "target_type": TargetType.USER,
        "target_ids": [_MARKER],
        "ip": _IP,
        "metadata": {"name_changed": True, "email_changed": False},
    }
    kwargs.update(overrides)
    return kwargs


def _profile_event(metadata: Any) -> AuditEvent:
    """An AuditEvent of user.profile_change on one target user with the given metadata."""
    action = _profile_change()
    return _event(
        action=action, target_type=TargetType.USER, target_ids=(_MARKER,), metadata=metadata
    )


class TestUserProfileChangeAction:
    """GH-164's org-scoped user.profile_change and its bool-only metadata."""

    def test_audit_events_profile_change_member_has_contract_value(self) -> None:
        """AuditAction.USER_PROFILE_CHANGE is "user.profile_change"."""
        member = getattr(AuditAction, "USER_PROFILE_CHANGE", None)

        assert member is not None, "AuditAction must define USER_PROFILE_CHANGE"
        assert member.value == _PROFILE_CHANGE
        assert AuditAction(_PROFILE_CHANGE) is member

    def test_audit_events_profile_change_is_org_scoped(self) -> None:
        """The event belongs to the org's log (the org's admins see it), and the actions
        the user-management routes also write keep their scopes."""
        assert ACTION_SCOPES[_profile_change()] == "org"
        assert ACTION_SCOPES[AuditAction.USER_ROLE_CHANGE] == "org"
        assert ACTION_SCOPES[AuditAction.SESSION_FORCE_LOGOUT] == "org"
        assert ACTION_SCOPES[AuditAction.USER_ACTIVATE] == "any"
        assert ACTION_SCOPES[AuditAction.USER_DEACTIVATE] == "any"
        assert ACTION_SCOPES[AuditAction.USER_DELETE] == "any"
        assert ACTION_SCOPES[AuditAction.PASSWORD_RESET_REQUEST] == "any"

    @pytest.mark.parametrize(("name_changed", "email_changed"), _PROFILE_FLAGS)
    def test_audit_events_profile_change_flags_metadata_is_valid(
        self, name_changed: bool, email_changed: bool
    ) -> None:
        """{"name_changed": bool, "email_changed": bool} validates and stays bools."""
        metadata = {"name_changed": name_changed, "email_changed": email_changed}

        event = _profile_event(metadata)

        assert event.metadata == metadata
        assert type(event.metadata["name_changed"]) is bool
        assert type(event.metadata["email_changed"]) is bool

    def test_audit_events_profile_change_contract_example_is_valid(self) -> None:
        """The contract's example: the name changed, the email didn't."""
        event = _profile_event({"name_changed": True, "email_changed": False})

        assert event.action == _profile_change()
        assert event.metadata == {"name_changed": True, "email_changed": False}

    def test_audit_events_profile_change_email_taken_metadata_is_valid(self) -> None:
        """The refused change on a taken email is recorded as {"email_taken": True}."""
        event = _profile_event({"email_taken": True})

        assert event.metadata == {"email_taken": True}

    @pytest.mark.parametrize("metadata", _PROFILE_CONTENT_METADATA)
    def test_audit_events_profile_change_content_metadata_is_refused(
        self, metadata: dict[str, Any]
    ) -> None:
        """An email address or a name as a metadata value is content: refused."""
        action = _profile_change()

        with pytest.raises(ValidationError):
            _event(
                action=action, target_type=TargetType.USER, target_ids=(_MARKER,), metadata=metadata
            )

    async def test_audit_events_record_profile_change_is_stored(self, conn: MagicMock) -> None:
        """The contract's row: the Org Admin as a member actor, their org, the changed user
        as the target, the client IP and the two flags."""
        await record(conn, **_profile_record_kwargs())

        row = _inserted_row(conn)
        assert row["action"] == _PROFILE_CHANGE
        assert row["org_id"] == _ORG
        assert (row["actor_kind"], row["actor_user_id"]) == ("member", _USER)
        assert row["target_type"] == "user"
        assert json.loads(row["target_ids"]) == [str(_MARKER)]
        assert str(row["ip"]) == _IP
        assert json.loads(row["metadata"]) == {"name_changed": True, "email_changed": False}

    async def test_audit_events_record_profile_change_email_taken_is_stored(
        self, conn: MagicMock
    ) -> None:
        await record(conn, **_profile_record_kwargs(metadata={"email_taken": True}))

        assert json.loads(_inserted_row(conn)["metadata"]) == {"email_taken": True}

    @pytest.mark.parametrize(
        ("actor_kind", "actor_user_id"),
        [
            pytest.param("member", _USER, id="member"),
            pytest.param("super_admin", _SUPER_ADMIN, id="super-admin"),
        ],
    )
    async def test_audit_events_record_profile_change_without_org_is_refused(
        self, conn: MagicMock, actor_kind: str, actor_user_id: UUID
    ) -> None:
        """Without an org_id the event has no log to land in: refused before any SQL."""
        kwargs = _profile_record_kwargs(
            actor_kind=actor_kind, actor_user_id=actor_user_id, org_id=None
        )

        with pytest.raises(AuditRecordError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("metadata", _PROFILE_CONTENT_METADATA)
    async def test_audit_events_record_profile_change_content_is_refused(
        self, conn: MagicMock, metadata: dict[str, Any]
    ) -> None:
        """record() refuses a name or an address (AuditRecordError) and writes nothing."""
        kwargs = _profile_record_kwargs(metadata=metadata)

        with pytest.raises(AuditRecordError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_profile_change_error_repeats_no_address(
        self, conn: MagicMock
    ) -> None:
        """The refusal carries neither the rejected address nor the IDs."""
        kwargs = _profile_record_kwargs(
            metadata={"name_changed": False, "email_changed": True, "new_email": "quokka@zoo.ch"}
        )

        with pytest.raises(AuditRecordError) as caught:
            await record(conn, **kwargs)

        _assert_no_content(str(caught.value), "quokka", _ORG, _USER, _MARKER)
        _assert_no_content(repr(caught.value), "quokka", _ORG, _USER, _MARKER)
        assert caught.value.__cause__ is None


# ---------------------------------------------------------------------------
# GH-166: password.change (a user changes their own password)
# ---------------------------------------------------------------------------

_PASSWORD_CHANGE = "password.change"

# Content in place of (or next to) the revoked-session count: always refused.
_PASSWORD_CHANGE_CONTENT_METADATA: list[Any] = [
    pytest.param({"sessions_revoked": 2, "new_password": "Correct Horse 42"}, id="new-password"),
    pytest.param({"sessions_revoked": 2, "old_password": "hunter2 hunter2"}, id="old-password"),
    pytest.param({"password": "Tr0ub4dor&3"}, id="password-key"),
    pytest.param({"sessions_revoked": "all of them"}, id="count-as-free-text"),
    pytest.param({"sessions_revoked": 2, "email": "ada@example.ch"}, id="email"),
    pytest.param({"sessions_revoked": 2, "hash": "$argon2id$v=19$m=65536"}, id="hash"),
    pytest.param({"sessions_revoked": 2, "name": "Ada Lovelace"}, id="name"),
]


def _password_change() -> AuditAction:
    """The AuditAction for password.change (raises ValueError until it exists)."""
    return AuditAction(_PASSWORD_CHANGE)


def _password_change_record_kwargs(**overrides: Any) -> dict[str, Any]:
    """record() keyword arguments for the contract's row: a member changed their password."""
    kwargs: dict[str, Any] = {
        "action": _password_change(),
        "actor_kind": "member",
        "actor_user_id": _USER,
        "org_id": _ORG,
        "target_type": TargetType.USER,
        "target_ids": [_USER],
        "ip": _IP,
        "metadata": {"sessions_revoked": 2},
    }
    kwargs.update(overrides)
    return kwargs


class TestPasswordChangeAction:
    """GH-166's any-scoped password.change and its count-only metadata."""

    def test_audit_events_password_change_member_has_contract_value(self) -> None:
        """AuditAction.PASSWORD_CHANGE is "password.change"."""
        member = getattr(AuditAction, "PASSWORD_CHANGE", None)

        assert member is not None, "AuditAction must define PASSWORD_CHANGE"
        assert member.value == _PASSWORD_CHANGE
        assert AuditAction(_PASSWORD_CHANGE) is member

    def test_audit_events_password_change_is_any_scoped(self) -> None:
        """A member's change lands in their org's log; a Super Admin's has no org."""
        assert ACTION_SCOPES[_password_change()] == "any"

    def test_audit_events_password_change_member_event_carries_the_org(self) -> None:
        """A member changing their own password: their org, themself as the target."""
        action = _password_change()

        event = _event(
            action=action,
            target_type=TargetType.USER,
            target_ids=(_USER,),
            metadata={"sessions_revoked": 2},
        )

        assert event.action == action
        assert event.org_id == _ORG
        assert event.target_ids == (_USER,)
        assert event.metadata == {"sessions_revoked": 2}
        assert type(event.metadata["sessions_revoked"]) is int

    def test_audit_events_password_change_super_admin_event_has_no_org(self) -> None:
        """The Super Admin changing their own password: no org."""
        action = _password_change()

        event = _event(
            action=action,
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_type=TargetType.USER,
            target_ids=(_SUPER_ADMIN,),
            metadata={"sessions_revoked": 1},
        )

        assert event.org_id is None
        assert event.actor_kind == "super_admin"

    @pytest.mark.parametrize("count", [0, 1, 2, 37])
    def test_audit_events_password_change_session_count_is_valid(self, count: int) -> None:
        """{"sessions_revoked": <int>} validates and stays an int."""
        action = _password_change()

        event = _event(
            action=action,
            target_type=TargetType.USER,
            target_ids=(_USER,),
            metadata={"sessions_revoked": count},
        )

        assert event.metadata == {"sessions_revoked": count}
        assert type(event.metadata["sessions_revoked"]) is int

    @pytest.mark.parametrize("metadata", _PASSWORD_CHANGE_CONTENT_METADATA)
    def test_audit_events_password_change_content_metadata_is_refused(
        self, metadata: dict[str, Any]
    ) -> None:
        """A password, a hash, an email, a name or free text as a value is content: refused."""
        action = _password_change()

        with pytest.raises(ValidationError):
            _event(
                action=action, target_type=TargetType.USER, target_ids=(_USER,), metadata=metadata
            )

    async def test_audit_events_record_password_change_member_is_stored(
        self, conn: MagicMock
    ) -> None:
        """The contract's row: the member as the actor and the target, their org, the
        client IP and the revoked-session count."""
        await record(conn, **_password_change_record_kwargs())

        row = _inserted_row(conn)
        assert row["action"] == _PASSWORD_CHANGE
        assert row["org_id"] == _ORG
        assert (row["actor_kind"], row["actor_user_id"]) == ("member", _USER)
        assert row["target_type"] == "user"
        assert json.loads(row["target_ids"]) == [str(_USER)]
        assert str(row["ip"]) == _IP
        assert json.loads(row["metadata"]) == {"sessions_revoked": 2}

    async def test_audit_events_record_password_change_super_admin_is_stored(
        self, conn: MagicMock
    ) -> None:
        """The Super Admin's row has no org."""
        kwargs = _password_change_record_kwargs(
            actor_kind="super_admin",
            actor_user_id=_SUPER_ADMIN,
            org_id=None,
            target_ids=[_SUPER_ADMIN],
            metadata={"sessions_revoked": 1},
        )

        await record(conn, **kwargs)

        row = _inserted_row(conn)
        assert row["action"] == _PASSWORD_CHANGE
        assert row["org_id"] is None
        assert (row["actor_kind"], row["actor_user_id"]) == ("super_admin", _SUPER_ADMIN)
        assert json.loads(row["metadata"]) == {"sessions_revoked": 1}

    @pytest.mark.parametrize("metadata", _PASSWORD_CHANGE_CONTENT_METADATA)
    async def test_audit_events_record_password_change_content_is_refused(
        self, conn: MagicMock, metadata: dict[str, Any]
    ) -> None:
        """record() refuses content (AuditRecordError) and writes nothing."""
        kwargs = _password_change_record_kwargs(metadata=metadata)

        with pytest.raises(AuditRecordError):
            await record(conn, **kwargs)

        conn.execute.assert_not_awaited()

    async def test_audit_events_record_password_change_error_repeats_no_password(
        self, conn: MagicMock
    ) -> None:
        """The refusal carries neither the rejected password nor the IDs."""
        kwargs = _password_change_record_kwargs(
            metadata={"sessions_revoked": 2, "new_password": "Quokka Marmalade 7"}
        )

        with pytest.raises(AuditRecordError) as caught:
            await record(conn, **kwargs)

        _assert_no_content(str(caught.value), "Quokka", "Marmalade", _ORG, _USER)
        _assert_no_content(repr(caught.value), "Quokka", "Marmalade", _ORG, _USER)
        assert caught.value.__cause__ is None
