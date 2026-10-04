"""Shared in-memory database for the service and HTTP tests (GH-151 to GH-169).

``FakeDb`` stands in for the users, organizations, invitations, sessions,
password_reset_tokens, email_outbox, audit_events, login_throttle,
platform_settings, org_settings, user_settings, permissions, oauth_tokens and
memory tables behind a pool-shaped
object (``FakeDb.pool``). The real ``admino.auth``, ``admino.sessions``,
``admino.session_management``, ``admino.password_reset``,
``admino.invitations``, ``admino.organizations``, ``admino.email_outbox``,
``admino.audit_events``, ``admino.login_throttle`` and
``admino.scoped_settings`` code runs against it: each statement is recognised
by its table and verb, and its bind parameters are applied to the in-memory
tables, so a test can log in, list and revoke sessions, request and confirm a
password reset, send, list, revoke, resend and accept invitations, create,
change, deactivate, schedule, cancel and purge organizations, count failed
attempts and lock them out, read and change the platform, org and user
settings, and check the result.

Inputs: organizations, accounts and sessions added with ``add_org`` /
``add_account`` / ``open_session``; invitations, reset tokens, queued emails,
audit events, throttle counters and settings rows seeded with
``add_invitation`` / ``add_reset_token`` / ``add_email`` / ``add_audit`` /
``add_throttle`` / ``add_platform_settings`` / ``add_org_settings`` /
``add_user_settings`` / ``add_permissions``.
Outputs: the recorded calls (``calls``: method, SQL, args, which pool or
connection ran it and inside which transaction), the table state, the
outcome of every transaction (``transactions``: commit or rollback) and how
many transactions are open right now (``open_transactions``).

The settings scopes (GH-159, migration 0013):
- The old key/value ``settings`` table is dropped: any statement that reads,
  writes, creates or drops a table named ``settings`` fails with asyncpg's
  UndefinedTableError, as it would against the migrated database.
- ``platform_settings`` holds at most one row (``platform_row()``): ``id``
  (BOOLEAN primary key, default true, CHECK (id)), ``llm_provider`` (NOT NULL,
  one of infomaniak / vllm / anthropic / openai), ``infomaniak_model``,
  ``vllm_model``, ``anthropic_model``, ``openai_model`` (NULL or a name that
  fully matches ``[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}``: no trailing newline),
  the five limits (NOT NULL, no default: ``max_tool_calls_per_message`` 1 to
  100, ``max_pending_confirmations`` 1 to 50, ``confirmation_timeout_s`` 10 to
  3600, ``max_message_length`` 1 to 100000, ``max_context_messages`` 1 to 200),
  the platform defaults of migration 0014 (GH-160, ``PLATFORM_DEFAULTS``: each
  an INTEGER NOT NULL with a default and a BETWEEN CHECK, plus
  ``trash_min_days <= trash_max_days``), the platform model's capabilities
  and retry limit of migration 0022 (GH-242, ``PLATFORM_LLM_LIMITS``:
  ``max_input_tokens`` 1000 to 2000000, default 200000, and
  ``llm_max_retries`` 0 to 5, default 2, INTEGER NOT NULL; ``image_input``
  BOOLEAN NOT NULL, default true) and ``updated_at`` (NOT NULL, default
  now()).
- ``org_settings`` (``org_settings``, keyed by org id): ``org_id`` (primary
  key, references organizations ON DELETE CASCADE), the seven
  ``<tool>_enabled`` BOOLEANs (NOT NULL, default true), the org policies of
  migration 0023 (GH-169): ``instructions`` (TEXT NOT NULL, default '', CHECK
  ``char_length(instructions) <= 8000``) and ``ORG_POLICY_COLUMNS`` (each an
  INTEGER NOT NULL with a default and a BETWEEN CHECK:
  ``session_idle_timeout_minutes`` 15 to 480, default 60,
  ``session_max_lifetime_hours`` 1 to 72, default 12, ``trash_retention_days``
  0 to 90, default 30), and ``updated_at``. ``add_org_settings`` seeds a row
  (every column a keyword argument) and ``org_settings_row(org_id)`` reads a
  copy back.
- ``user_settings`` (``user_settings``, keyed by user id): ``user_id``
  (primary key, references users ON DELETE CASCADE), ``theme`` (NOT NULL,
  default 'light', one of light / dark / system), ``notifications_enabled``
  (NOT NULL, default true), ``notifications_task_done`` (GH-35, migration
  0015: NOT NULL, default false) and ``updated_at``.
- Every statement naming one of the three tables runs through the SQL
  reader. Written rows must satisfy the migration: a value of the wrong
  Python type (a non-bool for a BOOLEAN, a non-int for an INTEGER, a non-str
  for a TEXT, a naive datetime) is a DataError, a missing NOT NULL value a
  NotNullViolationError, a broken CHECK a CheckViolationError, a taken key a
  UniqueViolationError and an org or user that doesn't exist a
  ForeignKeyViolationError. Deleting a users row deletes its user_settings
  row; deleting an organizations row deletes its org_settings row (CASCADE).
- ``permissions`` (GH-161, the org-scoped tool permission matrix): ``org_id``
  (UUID NOT NULL, references organizations ON DELETE CASCADE), ``tool`` and
  ``action`` (TEXT NOT NULL, CHECK ``~ '^[a-z][a-z0-9_]{0,62}$'``),
  ``permission`` (TEXT NOT NULL, one of allow / confirm / deny) and
  ``updated_at`` (NOT NULL, default now()); primary key (org_id, tool,
  action). It runs through the same settings-table reader (the conflict
  target of ON CONFLICT is the three-column key). Deleting an organizations
  row deletes its permissions rows. ``add_permissions(org_id)`` seeds an
  org's matrix (``DEFAULT_PERMISSIONS`` unless rows are given) and
  ``org_permissions(org_id)`` reads it back as tool -> {action: state}.
- ``oauth_tokens`` (GH-162, migration 0017: one row per user and provider):
  ``user_id`` (UUID NOT NULL, references users ON DELETE CASCADE), ``org_id``
  (UUID NOT NULL, references organizations ON DELETE CASCADE), ``provider``
  (TEXT NOT NULL, google / microsoft), ``encrypted_refresh_token`` (TEXT NOT
  NULL, 1 to 4096 characters), ``email`` (NULL or at most 254 characters),
  ``scopes`` (JSONB NOT NULL: a JSON array of at most 50 items; asyncpg has no
  JSONB codec here, so it is sent and returned as a JSON str), ``healthy``
  (BOOLEAN NOT NULL, default true), ``created_at`` and ``last_refreshed_at``
  (NOT NULL, default now()); primary key (user_id, provider).
  ``add_oauth_token`` seeds a row and ``oauth_token(user_id, provider)`` reads
  one back.
- ``memory`` (GH-162, migration 0017: each user's notes): ``user_id`` and
  ``org_id`` (as above, both ON DELETE CASCADE), ``key`` (TEXT NOT NULL, CHECK
  ``~ '^[a-zA-Z0-9_. -]{1,200}$'``), ``value`` (TEXT NOT NULL, at most 2000
  characters), ``created_at`` and ``updated_at`` (NOT NULL, default now());
  primary key (user_id, key). ``add_memory`` seeds a note and
  ``memories_of(user_id)`` reads a user's notes back as key -> value.
- Deleting a users row deletes its oauth_tokens and memory rows; deleting an
  organizations row deletes its org's rows of both tables (CASCADE).
- The SQL forms the reader runs on these tables (``$n`` bind parameters,
  optionally cast, literals, ``DEFAULT``, ``now()`` and ``coalesce(...)``
  anywhere a value goes):
  - ``INSERT INTO t [AS a] (cols) VALUES (exprs) [ON CONFLICT [(key)] DO
    NOTHING | ON CONFLICT (key) DO UPDATE SET col = expr, ... [WHERE ...]]
    [RETURNING ...]``. The conflict target must be the table's primary key.
    In DO UPDATE, ``EXCLUDED.col`` is the proposed row and ``t.col`` (or
    ``a.col``) the stored one; an unqualified column is ambiguous, as in
    PostgreSQL. The proposed row's CHECKs run before the conflict check.
  - ``INSERT INTO t (cols) SELECT ... FROM ...`` (one row per selected row;
    what migration 0013 seeds with).
  - ``SELECT cols FROM t [WHERE key = $n] [FOR UPDATE]`` (FOR UPDATE is
    recorded, no effect); ``WHERE id``, ``WHERE id = true`` and ``WHERE id IS
    TRUE`` on platform_settings.
  - ``UPDATE t SET col = coalesce($n, col), ..., updated_at = now() [WHERE
    ...] [RETURNING ...]`` and ``DELETE FROM t [WHERE ...]``.
  - Aggregates over all rows, without GROUP BY: ``SELECT bool_and(col) AS x,
    ... FROM org_settings`` (also ``every``, ``bool_or``, ``count`` and
    ``coalesce(bool_and(col), true)``). An aggregate over no rows is NULL
    (count: 0), as in PostgreSQL; FOR UPDATE with an aggregate fails with
    FeatureNotSupportedError.

The login throttle (GH-157):
- ``throttle`` holds the login_throttle rows of migration 0012 (scope,
  subject, failures, window_started_at, locked_until, expires_at), one dict
  per row; ``throttle_row(scope, subject)`` finds one and ``add_throttle``
  seeds one. ``account_subject(email)`` is what the database computes as the
  account subject: ``sha256(convert_to(lower(<email>), 'UTF8'))``.
- Every statement that names login_throttle runs through the SQL reader:
  INSERT (``ON CONFLICT (scope, subject) DO NOTHING`` included: a row whose
  key exists is skipped, after its CHECKs ran, as in PostgreSQL), SELECT
  (``FOR UPDATE`` recorded, no effect), UPDATE and DELETE. So does a
  FROM-less SELECT that computes a digest (``SELECT sha256(convert_to(
  lower($n), 'UTF8'))``).
- The table has no column defaults: a missing value is a
  NotNullViolationError. Written rows must satisfy migration 0012's rules:
  scope 'account' or 'ip', a 32-byte bytea subject, failures an int >= 0,
  ``expires_at > window_started_at``, ``locked_until IS NULL OR expires_at >=
  locked_until`` (CheckViolationError) and the (scope, subject) primary key
  (UniqueViolationError). A subject that isn't bytes, failures that aren't an
  int and a naive datetime (asyncpg would read it as local time) raise
  DataError. The key of a stored row never changes.
- Value expressions also include ``sha256(<bytea>)``, ``convert_to(<text>,
  'UTF8')``, ``greatest(...)`` / ``least(...)`` (NULLs ignored),
  ``interval '<n> <unit>'``, ``make_interval(<unit> => <value>)`` and binary
  ``+`` / ``-``.

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
- Every statement that names ``invitations`` or has ``organizations`` as its
  main table, every INSERT, UPDATE and DELETE on ``users``, every ``SELECT
  EXISTS`` and every ``fetch`` on users, every other users SELECT scoped by
  ``org_id = $n`` alone, and every SELECT on ``audit_events`` runs through a
  small SQL reader
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
  (OR, BETWEEN, CASE, CTEs, correlated subqueries, any ON CONFLICT but
  login_throttle's DO NOTHING, another table in a join, ...): an unrecognised
  statement on these tables never silently returns None, [] or "OK".
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
- GH-164: a users SELECT by ``id = $n`` within ``org_id = $n`` (the Org Admin
  user routes) runs on the reader too, so its status and deleted_at
  predicates and every selected column apply. The last-admin guard's query
  (``accounts.ensure_not_last_active_admin``, with its OR) is emulated
  exactly: the target's row if it belongs to the org, plus the org's active
  Org Admins, flagged ``is_active_admin``, in id order. ``DELETE FROM
  password_reset_tokens WHERE user_id = $n`` deletes the user's reset token.
  Queued emails record their ``recipient_address``, copied from the users row
  when queued (an email change notifies the old address).
- GH-166: ``users`` gains ``timezone`` (NULL or an IANA-shaped name, at most
  64 characters) and ``personal_instructions`` (NOT NULL, default '', at most
  1500 characters), checked like migration 0021's CHECKs, and
  ``response_language`` is checked too (NULL or de/fr/it/en). A users SELECT
  whose select list names either new column runs on the reader. The reader
  evaluates ``CASE WHEN <$n boolean | predicate> THEN <value> ELSE <value>
  END`` as a value (one WHEN branch). A ``fetchval`` users lookup by id that
  selects one column (``SELECT email FROM users WHERE id = $1``) returns that
  column.
- ``after_invitation_lookup`` runs once, right after the first SELECT on
  invitations bound to a token hash (a concurrent accept, revoke, rotation or
  expiry between the lookup and the transaction).

The organization lifecycle (GH-154):
- INSERT, UPDATE, DELETE and SELECT (``FOR UPDATE`` included) on
  organizations run through the SQL reader. An INSERT gets the schema's
  defaults (a new id, status 'active', data_residency true,
  default_response_language 'en', created_at and updated_at now); name, seats,
  monthly_budget_chf and storage_quota_bytes have none (NotNullViolationError).
  Every written row must satisfy all of migration 0004's organizations CHECKs
  (CheckViolationError): a 1 to 120 character name, 1 to 100000 seats, a
  budget and a quota >= 0, a known status and response language,
  ``(status = 'pending_deletion') = (purge_after IS NOT NULL)`` and
  ``(deletion_requested_at IS NULL) = (purge_after IS NULL)``. The budget is
  stored like NUMERIC(12,2): converted as asyncpg does (``Decimal(value)``)
  and rounded to 2 places (NumericValueOutOfRangeError beyond 10 integer
  digits); an id that exists already raises UniqueViolationError.
  Nothing sets updated_at but the statement itself (there is no trigger).
- Value expressions also include ``coalesce(a, b, ...)`` and
  ``now() + make_interval(days|hours|mins|secs => $n)``.
- ``DELETE FROM organizations`` behaves like ON DELETE RESTRICT: while any
  users row (users.org_id) or any audit row (audit_events.org_id) references
  the org, it raises ForeignKeyViolationError and deletes nothing.
  ``DELETE FROM users WHERE org_id = $1`` deletes every user of the org
  whatever its status, and each deleted user cascades to its sessions,
  invitation, email_outbox rows and reset token.
- ``SELECT purge_org_audit_events($n)`` emulates the function of migrations
  0011 and 0019: unless that org exists with status pending_deletion and
  ``purge_after <= now()`` it raises InsufficientPrivilegeError; while a users
  row still names the org it raises ForeignKeyViolationError (users.org_id is
  ON DELETE RESTRICT) and changes nothing; otherwise it deletes that org's
  audit rows, then the organizations row (its cascades included, GH-220), and
  returns how many audit rows it deleted. Every other DELETE, UPDATE or TRUNCATE that
  touches audit_events raises InsufficientPrivilegeError, like the
  append-only trigger, and any other TRUNCATE fails the test.
- Audit rows keep every column (id, occurred_at, org_id, actor_user_id,
  actor_kind, action, target_type, target_ids as a list of strings, ip as a
  string, metadata as a dict). An audit row whose org_id names no org fails
  like the foreign key. ``fail_audit_when`` (a predicate on the parsed row)
  makes only matching audit INSERTs fail. SELECTs on audit_events run through
  the SQL reader.
- ``fail_sql`` (a regex over the normalized SQL) makes matching statements
  fail with a driver error (DeadlockDetectedError), for "a database step
  fails" tests.
- ``after_org_lookup`` runs once, right after the first SELECT whose main
  table is organizations (a concurrent change between a lookup and a lock).

The sessions table is the schema after migration 0009 (GH-152):
- Each row stores its own ``idle_timeout_minutes`` (15 to 480, NOT NULL, no
  default: an INSERT without it fails like PostgreSQL's NotNullViolationError)
  and its ``expires_at`` (at most 72 hours after ``created_at``); both CHECKs
  are enforced (CheckViolationError).
- There is no ``revoked_at`` column: revoking a session deletes its row. Any
  statement that names ``revoked_at`` fails with asyncpg's
  UndefinedColumnError, as it would against the migrated database.
- ``created_at`` and ``last_seen_at`` default to the fake's now.
- GH-160: ``UPDATE sessions SET idle_timeout_minutes = $a, expires_at =
  created_at + make_interval(hours => $b) WHERE user_id IN (SELECT id FROM
  users WHERE kind = 'super_admin')`` changes every Super Admin session (and
  no member's), after checking both CHECKs on every row; it answers
  ``UPDATE <count>``.
- GH-169: the same statement scoped ``WHERE user_id IN (SELECT id FROM users
  WHERE org_id = $n) AND expires_at > now() AND last_seen_at +
  make_interval(mins => idle_timeout_minutes) > now()``
  (``admino.sessions.apply_org_policy``, contract §3) changes every LIVE
  session of every user of that org (any role, status or deletion), never
  another org's or a Super Admin's, with the same CHECKs; it answers
  ``UPDATE <count of the live rows>``. The live predicates read the OLD row
  values: a session that had already ended (expired, or idle past its old
  timeout) is neither changed nor counted. The form without both live
  predicates is refused (AssertionError), as is any other session-policy
  UPDATE the fake doesn't know.

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
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
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
# GH-164: accounts.ensure_not_last_active_admin's guard query (normalized).
_LAST_ADMIN_GUARD_RE: Final = re.compile(
    r"select id, \(role = 'org_admin' and status = 'active' and deleted_at is null\)"
    r" as is_active_admin from users where org_id = \$1 and \(id = \$2 or \(role ="
    r" 'org_admin' and status = 'active' and deleted_at is null\)\) order by id for update"
)
# GH-164: an email change deletes the user's live reset token.
_DELETE_USER_TOKEN_RE: Final = re.compile(
    r"delete from password_reset_tokens where user_id = \$\d+(?: returning user_id)?"
)

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
# GH-160: the platform session policy applied to every open Super Admin session
# (admino.sessions.apply_super_admin_policy), normalized.
_SUPER_ADMIN_POLICY_RE: Final = re.compile(
    r"update sessions set idle_timeout_minutes = \$(?P<idle>\d+)(?:::int(?:eger|4)?)?, "
    r"expires_at = created_at \+ make_interval\(hours => \$(?P<hours>\d+)(?:::int(?:eger|4)?)?\) "
    r"where user_id in \(select id from users where kind = 'super_admin'\)"
)
# GH-169: an org's session policy applied to every LIVE session of its users
# (admino.sessions.apply_org_policy, contract §3), normalized. The WHERE carries
# both live predicates (any spelling LIVE_EXPIRY_RE / LIVE_IDLE_RE accept, in
# either order), read against the OLD row values: a session that had already
# ended is never re-timed (so never revived by a longer policy). The form without
# them is not this statement any more.
_ORG_POLICY_SCOPE: Final = (
    r"update sessions set idle_timeout_minutes = \$(?P<idle>\d+)(?:::int(?:eger|4)?)?, "
    r"expires_at = created_at \+ make_interval\(hours => \$(?P<hours>\d+)(?:::int(?:eger|4)?)?\) "
    r"where user_id in \(select id from users where org_id = \$(?P<org>\d+)(?:::uuid)?\) "
)
_LIVE_ONLY: Final = (
    rf"(?:and {LIVE_EXPIRY_RE} and {LIVE_IDLE_RE}|and {LIVE_IDLE_RE} and {LIVE_EXPIRY_RE})"
)
_ORG_POLICY_RE: Final = re.compile(_ORG_POLICY_SCOPE + _LIVE_ONLY)

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
        # GH-166: migration 0021's account self-service columns.
        "timezone",
        "personal_instructions",
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
# The audit_events columns of migration 0005 (read-only through the reader).
_AUDIT_COLUMNS: Final = frozenset(
    {
        "id",
        "occurred_at",
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
# The login_throttle columns of migration 0012 (GH-157): no email, no IP text.
_THROTTLE_COLUMNS: Final = frozenset(
    {"scope", "subject", "failures", "window_started_at", "locked_until", "expires_at"}
)
# What the test side assumes as the failure window when it seeds a row
# (admino.login_throttle.FAILURE_WINDOW).
THROTTLE_WINDOW: Final = timedelta(minutes=15)

# GH-159: the settings scopes of migration 0013.
TOOL_NAMES: Final = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
    "memory",
)
LLM_PROVIDERS: Final = frozenset({"infomaniak", "vllm", "anthropic", "openai"})
THEMES: Final = frozenset({"light", "dark", "system"})
MODEL_COLUMNS: Final = ("infomaniak_model", "vllm_model", "anthropic_model", "openai_model")
# The model-name CHECK of migration 0013, read the way PostgreSQL reads it
# ('^...$' anchors the whole value: a trailing newline doesn't match).
MODEL_NAME_RE: Final = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}")
LIMIT_BOUNDS: Final[dict[str, tuple[int, int]]] = {
    "max_tool_calls_per_message": (1, 100),
    "max_pending_confirmations": (1, 50),
    "confirmation_timeout_s": (10, 3600),
    "max_message_length": (1, 100000),
    "max_context_messages": (1, 200),
}
# GH-160: the platform defaults of migration 0014, column -> (default, low, high).
# Every one is an INTEGER NOT NULL with a DEFAULT and a BETWEEN CHECK; the
# trash bounds also CHECK (trash_min_days <= trash_max_days).
PLATFORM_DEFAULTS: Final[dict[str, tuple[int, int, int]]] = {
    "max_file_size_mb": (50, 1, 500),
    "max_files_per_message": (10, 1, 50),
    "max_pages_per_file": (100, 1, 1000),
    "render_dpi": (150, 72, 300),
    "trash_min_days": (0, 0, 90),
    "trash_max_days": (90, 0, 90),
    "audit_months": (12, 6, 84),
    "org_deletion_grace_days": (30, 7, 90),
    "rate_limit_per_minute": (20, 1, 600),
    "lockout_after_failures": (10, 3, 100),
    "lockout_window_minutes": (15, 1, 1440),
    "lockout_minutes": (15, 1, 1440),
    "session_idle_timeout_minutes": (60, 15, 480),
    "session_max_lifetime_hours": (12, 1, 72),
}
# GH-242: the platform model's capabilities and LLM retry limit (migration 0022),
# column -> (default, low, high): each an INTEGER NOT NULL with a DEFAULT and a
# BETWEEN CHECK. ``image_input`` is a BOOLEAN NOT NULL DEFAULT true.
PLATFORM_LLM_LIMITS: Final[dict[str, tuple[int, int, int]]] = {
    "max_input_tokens": (200000, 1000, 2000000),
    "llm_max_retries": (2, 0, 5),
}
_PLATFORM_SETTINGS_COLUMNS: Final = frozenset(
    {
        "id",
        "llm_provider",
        *MODEL_COLUMNS,
        *PLATFORM_LLM_LIMITS,
        "image_input",
        *LIMIT_BOUNDS,
        *PLATFORM_DEFAULTS,
        "updated_at",
    }
)
# GH-169: migration 0023's org policies, column -> (default, low, high): each an
# INTEGER NOT NULL with a DEFAULT and a BETWEEN CHECK. ``instructions`` is a
# TEXT NOT NULL DEFAULT '' with CHECK (char_length(instructions) <= 8000).
ORG_POLICY_COLUMNS: Final[dict[str, tuple[int, int, int]]] = {
    "session_idle_timeout_minutes": (60, 15, 480),
    "session_max_lifetime_hours": (12, 1, 72),
    "trash_retention_days": (30, 0, 90),
}
ORG_INSTRUCTIONS_MAX: Final = 8000
_ORG_SETTINGS_COLUMNS: Final = frozenset(
    {
        "org_id",
        *(f"{tool}_enabled" for tool in TOOL_NAMES),
        "instructions",
        *ORG_POLICY_COLUMNS,
        "updated_at",
    }
)
_USER_SETTINGS_COLUMNS: Final = frozenset(
    {"user_id", "theme", "notifications_enabled", "notifications_task_done", "updated_at"}
)
# GH-161: the org-scoped permission matrix (the recreated permissions table).
_PERMISSIONS_COLUMNS: Final = frozenset({"org_id", "tool", "action", "permission", "updated_at"})
PERMISSION_STATES: Final = frozenset({"allow", "confirm", "deny"})
# The identifier CHECK on permissions.tool and permissions.action, read the way
# PostgreSQL reads '^[a-z][a-z0-9_]{0,62}$' (a trailing newline doesn't match).
IDENTIFIER_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,62}")
# GH-162: per-user OAuth connections and notes (the recreated oauth_tokens and memory).
_OAUTH_TOKEN_COLUMNS: Final = frozenset(
    {
        "user_id",
        "org_id",
        "provider",
        "encrypted_refresh_token",
        "email",
        "scopes",
        "healthy",
        "created_at",
        "last_refreshed_at",
    }
)
_MEMORY_COLUMNS: Final = frozenset(
    {"user_id", "org_id", "key", "value", "created_at", "updated_at"}
)
OAUTH_PROVIDERS: Final = frozenset({"google", "microsoft"})
# memory.key's CHECK ~ '^[a-zA-Z0-9_. -]{1,200}$', read the way PostgreSQL reads it.
MEMORY_KEY_RE: Final = re.compile(r"[a-zA-Z0-9_. -]{1,200}")
_SETTINGS_TABLES: Final = frozenset(
    {"platform_settings", "org_settings", "user_settings", "permissions", "oauth_tokens", "memory"}
)
# The primary key of every table an INSERT ... ON CONFLICT may name.
_CONFLICT_KEYS: Final[dict[str, tuple[str, ...]]] = {
    "platform_settings": ("id",),
    "org_settings": ("org_id",),
    "user_settings": ("user_id",),
    "permissions": ("org_id", "tool", "action"),
    "oauth_tokens": ("user_id", "provider"),
    "memory": ("user_id", "key"),
    "login_throttle": ("scope", "subject"),
}
# Column types of the settings tables (for asyncpg's encoders and the NOT NULLs).
_SETTINGS_TYPES: Final[dict[str, dict[str, str]]] = {
    "platform_settings": {
        "id": "bool",
        "llm_provider": "text",
        **dict.fromkeys(MODEL_COLUMNS, "text"),
        **dict.fromkeys(PLATFORM_LLM_LIMITS, "int"),
        "image_input": "bool",
        **dict.fromkeys(LIMIT_BOUNDS, "int"),
        **dict.fromkeys(PLATFORM_DEFAULTS, "int"),
        "updated_at": "timestamptz",
    },
    "org_settings": {
        "org_id": "uuid",
        **{f"{tool}_enabled": "bool" for tool in TOOL_NAMES},
        "instructions": "text",
        **dict.fromkeys(ORG_POLICY_COLUMNS, "int"),
        "updated_at": "timestamptz",
    },
    "user_settings": {
        "user_id": "uuid",
        "theme": "text",
        "notifications_enabled": "bool",
        "notifications_task_done": "bool",
        "updated_at": "timestamptz",
    },
    "permissions": {
        "org_id": "uuid",
        "tool": "text",
        "action": "text",
        "permission": "text",
        "updated_at": "timestamptz",
    },
    "oauth_tokens": {
        "user_id": "uuid",
        "org_id": "uuid",
        "provider": "text",
        "encrypted_refresh_token": "text",
        "email": "text",
        "scopes": "jsonb",
        "healthy": "bool",
        "created_at": "timestamptz",
        "last_refreshed_at": "timestamptz",
    },
    "memory": {
        "user_id": "uuid",
        "org_id": "uuid",
        "key": "text",
        "value": "text",
        "created_at": "timestamptz",
        "updated_at": "timestamptz",
    },
}
_SETTINGS_NULLABLE: Final[dict[str, frozenset[str]]] = {
    "platform_settings": frozenset(MODEL_COLUMNS),
    "org_settings": frozenset(),
    "user_settings": frozenset(),
    "permissions": frozenset(),
    "oauth_tokens": frozenset({"email"}),
    "memory": frozenset(),
}
# A statement on the old key/value settings table (dropped by migration 0013).
_OLD_SETTINGS_RE: Final = re.compile(
    r"(?<![\w.])(?:from|into|update|join|table|exists|truncate)\s+(?:only\s+)?"
    r"(?:public\.)?\"?settings\"?(?![\w])"
)
_AGGREGATE_RE: Final = re.compile(r"(?<![\w.])(?:count|bool_and|bool_or|every|min|max|sum) ?\(")

_COLUMNS: Final[dict[str, frozenset[str]]] = {
    "users": _USER_COLUMNS,
    "organizations": _ORG_COLUMNS,
    "invitations": _INVITATION_COLUMNS,
    "audit_events": _AUDIT_COLUMNS,
    "login_throttle": _THROTTLE_COLUMNS,
    "platform_settings": _PLATFORM_SETTINGS_COLUMNS,
    "org_settings": _ORG_SETTINGS_COLUMNS,
    "user_settings": _USER_SETTINGS_COLUMNS,
    "permissions": _PERMISSIONS_COLUMNS,
    "oauth_tokens": _OAUTH_TOKEN_COLUMNS,
    "memory": _MEMORY_COLUMNS,
}
# The tables the SQL reader writes (INSERT, UPDATE, DELETE).
_WRITABLE: Final = frozenset(
    {"users", "invitations", "organizations", "login_throttle", *_SETTINGS_TABLES}
)
_INTERVAL_UNITS: Final = {
    "sec": "seconds",
    "second": "seconds",
    "min": "minutes",
    "minute": "minutes",
    "hour": "hours",
    "day": "days",
}
_ORG_STATUSES: Final = frozenset({"active", "deactivated", "pending_deletion"})
_RESPONSE_LANGUAGES: Final = frozenset({"de", "fr", "it", "en"})
_CENT: Final = Decimal("0.01")
_MAX_BUDGET: Final = Decimal(10) ** 10  # NUMERIC(12,2): 10 integer digits
# The whole statement of migration 0011's purge function call.
_PURGE_ORG_AUDIT_RE: Final = re.compile(
    r"select (?:public\.)?purge_org_audit_events ?\( ?\$(\d+)(?: ?:: ?uuid)? ?\)(?: as (\w+))?;?"
)
# DML the append-only trigger of audit_events refuses (everything but the purges).
_AUDIT_REWRITE_RE: Final = re.compile(
    r"(?<![\w.])(?:delete from|update|truncate(?: table)?)(?: only)? (?:public\.)?audit_events\b"
)


# GH-166: migration 0021's users_timezone_check (the shape; the app checks the zone exists).
_TIMEZONE_COLUMN_RE: Final = re.compile(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*")


def _valid_timezone_column(value: Any) -> bool:
    """True for NULL or a value migration 0021's timezone CHECK accepts."""
    if value is None:
        return True
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and _TIMEZONE_COLUMN_RE.fullmatch(value) is not None
    )


def norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def sha256(token: str) -> bytes:
    """The stored form of a token: its raw SHA-256 digest."""
    return hashlib.sha256(token.encode()).digest()


def fake_hash(password: str) -> str:
    """The fast stand-in for passwords.hash_password."""
    return "fake$" + hashlib.sha256(password.encode()).hexdigest()


def account_subject(email: str) -> bytes:
    """The account subject the database computes for a typed email (GH-157):
    ``sha256(convert_to(lower(<email>), 'UTF8'))``, the fake's lower() being Python's."""
    return hashlib.sha256(email.lower().encode("utf-8")).digest()


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
        self.throttle: list[dict[str, Any]] = []
        # GH-159: the settings scopes (migration 0013).
        self.platform_settings: list[dict[str, Any]] = []
        self.org_settings: dict[uuid.UUID, dict[str, Any]] = {}
        self.user_settings: dict[uuid.UUID, dict[str, Any]] = {}
        # GH-161: the org-scoped permission matrix, keyed by (org_id, tool, action).
        self.permissions: dict[tuple[uuid.UUID, str, str], dict[str, Any]] = {}
        # GH-162: per-user connections keyed by (user_id, provider), notes by (user_id, key).
        self.oauth_tokens: dict[tuple[uuid.UUID, str], dict[str, Any]] = {}
        self.memory: dict[tuple[uuid.UUID, str], dict[str, Any]] = {}
        self.calls: list[Call] = []
        self.transactions: list[tuple[int, str]] = []
        self.open_transactions = 0
        self.fail_audit = False
        self.fail_audit_when: Callable[[dict[str, Any]], bool] | None = None
        self.fail_sql: str | None = None
        self.after_token_lookup: Callable[[], None] | None = None
        self.after_invitation_lookup: Callable[[], None] | None = None
        self.after_org_lookup: Callable[[], None] | None = None
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
        **fields: Any,
    ) -> uuid.UUID:
        """Create an organization, or change the given fields of an existing one.

        A new org is active with 100 seats, a budget of 0.00 and no storage
        quota; ORG_ID and OTHER_ORG_ID get ORG_NAME and OTHER_ORG_NAME, any
        other org a generated name. A pending_deletion org has its deletion
        dates set (the 0004 CHECKs): requested now, purge in 30 days. Any other
        organizations column can be set through ``fields`` (applied last, e.g.
        ``purge_after`` for an org that is due). Returns the org's id (a plain
        uuid.UUID).
        """
        unknown = set(fields) - _ORG_COLUMNS
        assert not unknown, f"organizations has no column {sorted(unknown)}"
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
                "monthly_budget_chf": Decimal("0.00"),
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
        row.update(fields)
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
        created_at: datetime | None = None,
        last_login_at: datetime | None = None,
        response_language: str | None = None,
        timezone: str | None = None,
        personal_instructions: str = "",
    ) -> uuid.UUID:
        """Add an account and return its id (a plain uuid.UUID).

        A member's org is created (active, 100 seats) if it doesn't exist.
        ``org_status`` overrides the org's status for this account's login,
        session and reset lookups only; left out, the account follows the
        organizations row. ``created_at`` defaults to one day ago and
        ``last_login_at`` to None (GH-164: the Org Admin user list shows both).
        ``response_language`` (None: the org default), ``timezone`` (None:
        not preset yet) and ``personal_instructions`` ('' : none) are the
        account self-service columns (GH-166, migration 0021).
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
            "response_language": response_language,
            "timezone": timezone,
            "personal_instructions": personal_instructions,
            "created_at": created_at or datetime.now(UTC) - timedelta(days=1),
            "last_login_at": last_login_at,
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
        created_ago: timedelta | None = None,
    ) -> str:
        """Store a session for the user and return its raw token.

        By default the session is live: seen just now, 60 minutes idle timeout,
        expiring in 12 hours. ``last_seen_ago`` / ``expires_in`` build idle or
        expired sessions (a row the purge job hasn't deleted yet).
        ``created_ago`` (GH-169) pins ``created_at`` to that long ago (default:
        the earlier of the last-seen time and an hour before the expiry).
        """
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        last_seen_at = now - last_seen_ago
        expires_at = now + expires_in
        if created_ago is not None:
            created_at = now - created_ago
        else:
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

    def add_invitation(self, user_id: uuid.UUID, *, sent_ago: timedelta = timedelta(0)) -> str:
        """Store an invitations row for a user (sent ``sent_ago``, 72 h lifetime); return
        its raw token."""
        token = secrets.token_urlsafe(32)
        sent_at = datetime.now(UTC) - sent_ago
        invitation_id = uuid.uuid4()
        self.invitations[invitation_id] = {
            "id": invitation_id,
            "user_id": user_id,
            "token_hash": sha256(token),
            "created_at": sent_at,
            "sent_at": sent_at,
            "expires_at": sent_at + INVITATION_MAX_LIFETIME,
            "accepted_at": None,
        }
        return token

    def add_reset_token(self, user_id: uuid.UUID) -> str:
        """Store a live password reset token for a user; return the raw token."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        self.tokens[user_id] = {
            "token_hash": sha256(token),
            "created_at": now,
            "expires_at": now + FAKE_LIFETIME,
        }
        return token

    def add_email(
        self,
        user_id: uuid.UUID,
        *,
        template_key: str = "invitation",
        status: str = "pending",
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store an email_outbox row for a user (a finished row has no params)."""
        finished = status != "pending"
        row = {
            "user_id": user_id,
            "template_key": template_key,
            "language": self.users[user_id]["ui_language"],
            "params": {} if finished else dict(params or {}),
            "status": status,
            "finished_at": datetime.now(UTC) if finished else None,
        }
        self.outbox.append(row)
        return row

    def add_audit(
        self,
        *,
        org_id: uuid.UUID | None,
        action: str = "tool.call",
        actor_kind: str = "member",
        actor_user_id: uuid.UUID | None = None,
        occurred_at: datetime | None = None,
        target_type: str | None = None,
        target_ids: tuple[uuid.UUID, ...] = (),
        ip: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> uuid.UUID:
        """Store an audit_events row as the database holds it; return its id.

        A member or Super Admin actor without a user id gets a random one (the
        actor CHECK); ``occurred_at`` defaults to now.
        """
        if actor_kind in {"member", "super_admin"} and actor_user_id is None:
            actor_user_id = uuid.uuid4()
        event_id = uuid.uuid4()
        self.audit.append(
            {
                "id": event_id,
                "occurred_at": occurred_at or datetime.now(UTC),
                "org_id": org_id,
                "actor_user_id": actor_user_id,
                "actor_kind": actor_kind,
                "action": action,
                "target_type": target_type,
                "target_ids": [str(target) for target in target_ids],
                "ip": ip,
                "metadata": dict(metadata or {}),
            }
        )
        return event_id

    def add_throttle(
        self,
        scope: str,
        subject: bytes,
        *,
        failures: int = 0,
        window_started_at: datetime | None = None,
        locked_until: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Store a login_throttle row as migration 0012 allows it; return the stored row.

        ``window_started_at`` defaults to now; ``expires_at`` to the moment the
        row stops having any effect: ``max(window_started_at + 15 minutes,
        locked_until)``. The row must satisfy the table's rules (a seeded row
        is one the database could hold).
        """
        started = window_started_at or datetime.now(UTC)
        if expires_at is None:
            expires_at = started + THROTTLE_WINDOW
            if locked_until is not None:
                expires_at = max(expires_at, locked_until)
        row = {
            "scope": scope,
            "subject": subject,
            "failures": failures,
            "window_started_at": started,
            "locked_until": locked_until,
            "expires_at": expires_at,
        }
        self._check_throttle(row, None)
        self.throttle.append(row)
        return row

    def add_platform_settings(self, **columns: Any) -> dict[str, Any]:
        """Store the platform_settings row (GH-159) as migration 0013 allows it; return it.

        Defaults: the LLMConfig and LimitsConfig defaults (provider infomaniak,
        its model and vllm's set, the Anthropic and OpenAI models NULL; 10, 3,
        300, 4000 and 20), migration 0014's column defaults for the platform
        defaults (``PLATFORM_DEFAULTS``) and migration 0022's for the model
        capabilities and retry limit (``PLATFORM_LLM_LIMITS``, image input
        true), updated now. Any column can be given.
        """
        unknown = set(columns) - _PLATFORM_SETTINGS_COLUMNS
        assert not unknown, f"platform_settings has no column {sorted(unknown)}"
        assert not self.platform_settings, "platform_settings holds one row at most"
        row: dict[str, Any] = {
            "id": True,
            "llm_provider": "infomaniak",
            "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
            "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
            "anthropic_model": None,
            "openai_model": None,
            **{column: default for column, (default, _, _) in PLATFORM_LLM_LIMITS.items()},
            "image_input": True,
            "max_tool_calls_per_message": 10,
            "max_pending_confirmations": 3,
            "confirmation_timeout_s": 300,
            "max_message_length": 4000,
            "max_context_messages": 20,
            **{column: default for column, (default, _, _) in PLATFORM_DEFAULTS.items()},
            "updated_at": datetime.now(UTC),
        }
        row.update(columns)
        self.check_settings("platform_settings", row, original=None)
        self.platform_settings.append(row)
        return row

    def add_org_settings(
        self,
        org_id: uuid.UUID,
        *,
        instructions: str = "",
        session_idle_timeout_minutes: int = 60,
        session_max_lifetime_hours: int = 12,
        trash_retention_days: int = 30,
        updated_at: datetime | None = None,
        **tools: bool,
    ) -> dict[str, Any]:
        """Store an org's org_settings row (GH-159, GH-169); every tool not given is enabled.

        ``tools`` are tool names (``gmail=False``), stored as ``<tool>_enabled``.
        The policy columns of migration 0023 default to its column defaults
        (instructions '', 60 minutes idle, 12 hours lifetime, 30 days trash) and
        are checked like its CHECKs (a value out of bounds is a CheckViolationError,
        a wrong type a DataError).
        """
        unknown = set(tools) - set(TOOL_NAMES)
        assert not unknown, f"no such tool {sorted(unknown)}"
        row: dict[str, Any] = {
            "org_id": org_id,
            **{f"{tool}_enabled": tools.get(tool, True) for tool in TOOL_NAMES},
            "instructions": instructions,
            "session_idle_timeout_minutes": session_idle_timeout_minutes,
            "session_max_lifetime_hours": session_max_lifetime_hours,
            "trash_retention_days": trash_retention_days,
            "updated_at": updated_at or datetime.now(UTC),
        }
        self.check_settings("org_settings", row, original=None)
        self.org_settings[row["org_id"]] = row
        return row

    def add_user_settings(
        self,
        user_id: uuid.UUID,
        *,
        theme: str = "light",
        notifications_enabled: bool = True,
        notifications_task_done: bool = False,
        updated_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Store a user's user_settings row (GH-159, GH-35)."""
        row: dict[str, Any] = {
            "user_id": user_id,
            "theme": theme,
            "notifications_enabled": notifications_enabled,
            "notifications_task_done": notifications_task_done,
            "updated_at": updated_at or datetime.now(UTC),
        }
        self.check_settings("user_settings", row, original=None)
        self.user_settings[user_id] = row
        return row

    def add_permissions(
        self,
        org_id: uuid.UUID,
        rows: dict[str, dict[str, str]] | None = None,
        *,
        updated_at: datetime | None = None,
    ) -> dict[str, dict[str, str]]:
        """Store an org's permission matrix (GH-161); ``DEFAULT_PERMISSIONS`` unless rows are given.

        ``rows`` is tool -> {action: state}. Rows already stored for the org are
        replaced one by one (a given key overwrites, the others stay).
        """
        from admino.permissions import DEFAULT_PERMISSIONS

        matrix = DEFAULT_PERMISSIONS if rows is None else rows
        for tool, actions in matrix.items():
            for action, state in actions.items():
                row: dict[str, Any] = {
                    "org_id": org_id,
                    "tool": tool,
                    "action": action,
                    "permission": state,
                    "updated_at": updated_at or datetime.now(UTC),
                }
                existing = self.permissions.get((_canonical(org_id), tool, action))
                self.check_settings("permissions", row, original=existing)
                self.permissions[(row["org_id"], tool, action)] = row
        return {tool: dict(actions) for tool, actions in matrix.items()}

    def org_permissions(self, org_id: uuid.UUID) -> dict[str, dict[str, str]]:
        """The stored matrix of an org as tool -> {action: state} (empty without rows)."""
        matrix: dict[str, dict[str, str]] = {}
        for (row_org, tool, action), row in sorted(self.permissions.items(), key=str):
            if row_org == _canonical(org_id):
                matrix.setdefault(tool, {})[action] = row["permission"]
        return matrix

    def add_oauth_token(
        self,
        user_id: uuid.UUID,
        provider: str,
        *,
        encrypted_refresh_token: str,
        org_id: uuid.UUID | None = None,
        email: str | None = None,
        scopes: list[str] | None = None,
        healthy: bool = True,
        created_at: datetime | None = None,
        last_refreshed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Store a user's oauth_tokens row for a provider (GH-162), replacing one they had.

        ``org_id`` defaults to the user's org; ``scopes`` (default ``["scope"]``) is
        stored as its JSON text, like asyncpg sends a JSONB value without a codec.
        """
        now = datetime.now(UTC)
        row: dict[str, Any] = {
            "user_id": user_id,
            "org_id": org_id if org_id is not None else self.users[_canonical(user_id)]["org_id"],
            "provider": provider,
            "encrypted_refresh_token": encrypted_refresh_token,
            "email": email,
            "scopes": json.dumps(["scope"] if scopes is None else scopes),
            "healthy": healthy,
            "created_at": created_at or now,
            "last_refreshed_at": last_refreshed_at or now,
        }
        existing = self.oauth_tokens.get((_canonical(user_id), provider))
        self.check_settings("oauth_tokens", row, original=existing)
        self.oauth_tokens[(row["user_id"], provider)] = row
        return row

    def oauth_token(self, user_id: uuid.UUID, provider: str) -> dict[str, Any] | None:
        """A user's stored oauth_tokens row for a provider, if any."""
        return self.oauth_tokens.get((_canonical(user_id), provider))

    def add_memory(
        self, user_id: uuid.UUID, key: str, value: str, *, org_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        """Store one of a user's notes (GH-162), replacing the note they had under the key.

        ``org_id`` defaults to the user's org.
        """
        now = datetime.now(UTC)
        row: dict[str, Any] = {
            "user_id": user_id,
            "org_id": org_id if org_id is not None else self.users[_canonical(user_id)]["org_id"],
            "key": key,
            "value": value,
            "created_at": now,
            "updated_at": now,
        }
        existing = self.memory.get((_canonical(user_id), key))
        self.check_settings("memory", row, original=existing)
        self.memory[(row["user_id"], key)] = row
        return row

    def memories_of(self, user_id: uuid.UUID) -> dict[str, str]:
        """A user's stored notes as key -> value (empty without any)."""
        return {
            key: row["value"]
            for (owner, key), row in sorted(self.memory.items(), key=str)
            if owner == _canonical(user_id)
        }

    def platform_row(self) -> dict[str, Any] | None:
        """The platform_settings row, if there is one."""
        return self.platform_settings[0] if self.platform_settings else None

    def org_settings_row(self, org_id: uuid.UUID) -> dict[str, Any] | None:
        """A copy of an org's stored org_settings row (GH-169), None without a row."""
        row = self.org_settings.get(_canonical(org_id))
        return dict(row) if row is not None else None

    def org_tools(self, org_id: uuid.UUID) -> dict[str, bool] | None:
        """The stored tool switches of an org by tool name (None without a row)."""
        row = self.org_settings.get(org_id)
        if row is None:
            return None
        return {tool: row[f"{tool}_enabled"] for tool in TOOL_NAMES}

    def throttle_row(self, scope: str, subject: bytes | None) -> dict[str, Any] | None:
        """The stored login_throttle row of (scope, subject), if there is one."""
        return next(
            (
                row
                for row in self.throttle
                if row["scope"] == scope and subject is not None and row["subject"] == subject
            ),
            None,
        )

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
                "throttle": self.throttle,
                "platform_settings": self.platform_settings,
                "org_settings": self.org_settings,
                "user_settings": self.user_settings,
                "permissions": self.permissions,
                "oauth_tokens": self.oauth_tokens,
                "memory": self.memory,
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
        self.throttle = state["throttle"]
        self.platform_settings = state["platform_settings"]
        self.org_settings = state["org_settings"]
        self.user_settings = state["user_settings"]
        self.permissions = state["permissions"]
        self.oauth_tokens = state["oauth_tokens"]
        self.memory = state["memory"]

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
        if _OLD_SETTINGS_RE.search(_masked_literals(n)):
            # Migration 0013 dropped the key/value settings table (GH-159).
            raise asyncpg.exceptions.UndefinedTableError('relation "settings" does not exist')
        if self.fail_sql is not None and re.search(self.fail_sql, n):
            raise asyncpg.exceptions.DeadlockDetectedError("deadlock detected")
        if _AUDIT_REWRITE_RE.search(n) or (n.startswith("truncate") and "audit_events" in n):
            # The append-only trigger (migrations 0005 and 0011): only the purge
            # functions delete audit rows.
            raise asyncpg.exceptions.InsufficientPrivilegeError("audit_events is append-only")
        assert not n.startswith("truncate"), f"the fake doesn't truncate: {n}"
        if purge := _PURGE_ORG_AUDIT_RE.fullmatch(n):
            return self._purge_org_audit_events(method, purge, args)
        if method == "fetch" and _LAST_ADMIN_GUARD_RE.fullmatch(n):
            return self._last_admin_guard_rows(args)
        if _runs_on_reader(method, n, args):
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
            if not any(isinstance(arg, bytes | bytearray) for arg in args):
                return self._delete_user_token(method, n, args)
            return self._consume_token(args)
        if method == "fetchrow" and "password_reset_tokens" in n:
            return self._token_row(args)
        if n.startswith("update users set password_hash"):
            return self._set_password(args)
        if n.startswith("insert into sessions"):
            return self._insert_session(method, sql, args)
        if n.startswith("delete from sessions"):
            return self._delete_sessions(method, n, args)
        if policy := _SUPER_ADMIN_POLICY_RE.fullmatch(n):
            return self._apply_super_admin_policy(policy, args)
        if policy := _ORG_POLICY_RE.fullmatch(n):
            return self._apply_org_policy(policy, args)
        assert not re.match(r"update sessions set idle_timeout_minutes\b", n), (
            f"a session-policy UPDATE the fake doesn't know (GH-169: the org form needs "
            f"both live-only predicates of contract §3): {n}"
        )
        if n.startswith("update sessions"):
            return self._touch_session(n, args)
        if method == "fetch" and re.search(r"\bfrom sessions\b", n):
            return self._list_sessions(n, args)
        if method == "fetchrow" and "sessions" in n:
            return self._session_row(n, args)
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
            org_hook = self.after_org_lookup
            if org_hook is not None and _primary_table(n) == "organizations":
                self.after_org_lookup = None
                org_hook()
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
        if table == "audit_events":
            return list(self.audit)
        if table == "login_throttle":
            return list(self.throttle)
        if table == "platform_settings":
            return list(self.platform_settings)
        if table == "org_settings":
            return list(self.org_settings.values())
        if table == "user_settings":
            return list(self.user_settings.values())
        if table == "permissions":
            return list(self.permissions.values())
        if table == "oauth_tokens":
            return list(self.oauth_tokens.values())
        if table == "memory":
            return list(self.memory.values())
        msg = f"the fake's SQL reader doesn't model table {table}"
        raise AssertionError(msg)

    # -- the settings tables of migration 0013 (GH-159) ----------------------------

    def settings_defaults(self, table: str, given: dict[str, Any], now: datetime) -> dict[str, Any]:
        """A new settings row: the column defaults (migrations 0013-0015), then the given values."""
        row: dict[str, Any] = dict.fromkeys(_COLUMNS[table])
        if table == "platform_settings":
            row["id"] = True
            row.update({column: default for column, (default, _, _) in PLATFORM_DEFAULTS.items()})
            row.update({column: default for column, (default, _, _) in PLATFORM_LLM_LIMITS.items()})
            row["image_input"] = True
        elif table == "org_settings":
            row.update({f"{tool}_enabled": True for tool in TOOL_NAMES})
            row["instructions"] = ""
            row.update({column: default for column, (default, _, _) in ORG_POLICY_COLUMNS.items()})
        elif table == "user_settings":
            row.update(theme="light", notifications_enabled=True, notifications_task_done=False)
        elif table == "oauth_tokens":
            row.update(healthy=True, created_at=now, last_refreshed_at=now)
        elif table == "memory":
            row["created_at"] = now
        if "updated_at" in row:
            row["updated_at"] = now
        row.update(given)
        return row

    def settings_by_key(self, table: str, row: dict[str, Any]) -> dict[str, Any] | None:
        """The stored settings row with the same primary key, if any."""
        keys = _CONFLICT_KEYS[table]
        for other in self.table_rows(table):
            if all(_canonical(other[key]) == _canonical(row[key]) for key in keys):
                return other
        return None

    def store_settings(self, table: str, row: dict[str, Any]) -> None:
        """Store a new, checked settings row."""
        if table == "platform_settings":
            self.platform_settings.append(row)
        elif table == "org_settings":
            self.org_settings[row["org_id"]] = row
        elif table == "permissions":
            self.permissions[(row["org_id"], row["tool"], row["action"])] = row
        elif table == "oauth_tokens":
            self.oauth_tokens[(row["user_id"], row["provider"])] = row
        elif table == "memory":
            self.memory[(row["user_id"], row["key"])] = row
        else:
            self.user_settings[row["user_id"]] = row

    def check_settings(
        self,
        table: str,
        row: dict[str, Any],
        *,
        original: dict[str, Any] | None,
        keys: bool = True,
    ) -> None:
        """Migration 0013's rules for a written settings row, as PostgreSQL applies them.

        Types first (asyncpg's encoders), then NOT NULL, the CHECKs and (unless
        ``keys`` is False) the primary key and the foreign key. A key given as
        a str is stored as a uuid.UUID, like the driver's uuid codec.
        """
        types = _SETTINGS_TYPES[table]
        for column, value in list(row.items()):
            assert column in types, f"{table} has no column {column}"
            if value is None:
                continue
            kind = types[column]
            valid = True
            if kind == "bool":
                valid = type(value) is bool
            elif kind == "int":
                valid = type(value) is int
            elif kind == "text":
                valid = isinstance(value, str)
            elif kind == "timestamptz":
                valid = isinstance(value, datetime) and value.tzinfo is not None
            elif kind == "jsonb":
                # No JSONB codec: asyncpg sends the JSON text and PostgreSQL parses it.
                valid = isinstance(value, str)
                if valid:
                    try:
                        json.loads(value)
                    except ValueError:
                        msg = "invalid input syntax for type json"
                        raise asyncpg.exceptions.InvalidTextRepresentationError(msg) from None
            elif isinstance(value, str):
                try:
                    row[column] = uuid.UUID(value)
                except ValueError:
                    valid = False
            else:
                valid = isinstance(value, uuid.UUID)
                if valid:
                    row[column] = _canonical(value)
            if not valid:
                msg = f"invalid input for query argument ({column}): {kind} expected"
                raise asyncpg.exceptions.DataError(msg)
        for column in types:
            if row.get(column) is None and column not in _SETTINGS_NULLABLE[table]:
                msg = f'null value in column "{column}" of relation "{table}"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        rules: list[tuple[str, bool]] = []
        if table == "platform_settings":
            rules.append(("id", row["id"] is True))
            rules.append(("llm_provider", row["llm_provider"] in LLM_PROVIDERS))
            rules.extend(
                (column, row[column] is None or MODEL_NAME_RE.fullmatch(row[column]) is not None)
                for column in MODEL_COLUMNS
            )
            rules.extend(
                (column, low <= row[column] <= high) for column, (low, high) in LIMIT_BOUNDS.items()
            )
            rules.extend(
                (column, low <= row[column] <= high)
                for column, (_, low, high) in PLATFORM_DEFAULTS.items()
            )
            rules.extend(
                (column, low <= row[column] <= high)
                for column, (_, low, high) in PLATFORM_LLM_LIMITS.items()
            )
            rules.append(("trash_bounds", row["trash_min_days"] <= row["trash_max_days"]))
        elif table == "org_settings":
            rules.append(("instructions", len(row["instructions"]) <= ORG_INSTRUCTIONS_MAX))
            rules.extend(
                (column, low <= row[column] <= high)
                for column, (_, low, high) in ORG_POLICY_COLUMNS.items()
            )
        elif table == "user_settings":
            rules.append(("theme", row["theme"] in THEMES))
        elif table == "permissions":
            rules.append(("permission", row["permission"] in PERMISSION_STATES))
            rules.append(("tool", IDENTIFIER_RE.fullmatch(row["tool"]) is not None))
            rules.append(("action", IDENTIFIER_RE.fullmatch(row["action"]) is not None))
        elif table == "oauth_tokens":
            scopes = json.loads(row["scopes"])
            rules.append(("provider", row["provider"] in OAUTH_PROVIDERS))
            rules.append(
                ("encrypted_refresh_token", 1 <= len(row["encrypted_refresh_token"]) <= 4096)
            )
            rules.append(("email", row["email"] is None or len(row["email"]) <= 254))
            rules.append(("scopes", isinstance(scopes, list) and len(scopes) <= 50))
        elif table == "memory":
            rules.append(("key", MEMORY_KEY_RE.fullmatch(row["key"]) is not None))
            rules.append(("value", len(row["value"]) <= 2000))
        for name, valid in rules:
            if not valid:
                msg = f'new row for relation "{table}" violates the {name} check'
                raise asyncpg.exceptions.CheckViolationError(msg)
        if not keys:
            return
        key_columns = _CONFLICT_KEYS[table]
        for other in self.table_rows(table):
            if other is not original and all(
                _canonical(other[key]) == _canonical(row[key]) for key in key_columns
            ):
                msg = f'duplicate key value violates unique constraint "{table}_pkey"'
                raise asyncpg.exceptions.UniqueViolationError(msg)
        if table == "permissions" and _canonical(row["org_id"]) not in self.orgs:
            msg = 'insert or update on table "permissions" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        if table == "org_settings" and _canonical(row["org_id"]) not in self.orgs:
            msg = 'insert or update on table "org_settings" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        if table == "user_settings" and _canonical(row["user_id"]) not in self.users:
            msg = 'insert or update on table "user_settings" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        if table in {"oauth_tokens", "memory"} and (
            _canonical(row["user_id"]) not in self.users
            or _canonical(row["org_id"]) not in self.orgs
        ):
            msg = f'insert or update on table "{table}" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)

    def normalized(self, table: str, values: dict[str, Any]) -> dict[str, Any]:
        """The values as the column types store them (asyncpg's encoders, NUMERIC(12,2))."""
        if table == "login_throttle":
            subject = values.get("subject")
            if isinstance(subject, bytearray | memoryview):
                return {**values, "subject": bytes(subject)}
            return values
        if table != "organizations":
            return values
        stored = dict(values)
        for column, kind in (
            ("name", str),
            ("status", str),
            ("seats", int),
            ("storage_quota_bytes", int),
            ("data_residency", bool),
        ):
            value = stored.get(column)
            if value is not None and not isinstance(value, kind):
                msg = f"invalid input for query argument ({column}): {kind.__name__} expected"
                raise asyncpg.exceptions.DataError(msg)
        budget = stored.get("monthly_budget_chf")
        if budget is not None:
            try:
                amount = budget if isinstance(budget, Decimal) else Decimal(budget)
                rounded = amount.quantize(_CENT, rounding=ROUND_HALF_UP)
            except (InvalidOperation, TypeError, ValueError):
                msg = "invalid input for query argument (monthly_budget_chf)"
                raise asyncpg.exceptions.DataError(msg) from None
            if not rounded.is_finite() or abs(rounded) >= _MAX_BUDGET:
                msg = "numeric field overflow"
                raise asyncpg.exceptions.NumericValueOutOfRangeError(msg)
            stored["monthly_budget_chf"] = rounded
        return stored

    def new_row(
        self,
        table: str,
        given: dict[str, Any],
        now: datetime,
        *,
        skip_conflict: bool = False,
    ) -> dict[str, Any] | None:
        """Build, check and store a new users, invitations, organizations or
        login_throttle row (an INSERT).

        ``skip_conflict``: ON CONFLICT (scope, subject) DO NOTHING on login_throttle:
        a row whose key exists is not stored (None), after its CHECKs ran.
        """
        if table == "login_throttle":
            # No column defaults (migration 0012): the app sets every value.
            row: dict[str, Any] = dict.fromkeys(_THROTTLE_COLUMNS)
            row.update(self.normalized(table, given))
            if skip_conflict and self.throttle_row(row["scope"], row["subject"]) is not None:
                self._check_throttle(row, None, check_key=False)
                return None
            self._check_throttle(row, None)
            self.throttle.append(row)
            return row
        assert not skip_conflict, f"the fake does ON CONFLICT on login_throttle only: {table}"
        if table == "users":
            row = dict.fromkeys(_USER_COLUMNS)
            row.update(
                id=uuid.uuid4(),
                status="invited",
                ui_language="en",
                personal_instructions="",  # GH-166: migration 0021's default
                created_at=now,
            )
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
        if table == "organizations":
            row = dict.fromkeys(_ORG_COLUMNS)
            row.update(
                id=uuid.uuid4(),
                status="active",
                data_residency=True,
                default_response_language="en",
                created_at=now,
                updated_at=now,
            )
            row.update(self.normalized("organizations", given))
            if row["id"] in self.orgs:
                msg = 'duplicate key value violates unique constraint "organizations_pkey"'
                raise asyncpg.exceptions.UniqueViolationError(msg)
            self.check_row("organizations", row, changed=set(_ORG_COLUMNS), original=None)
            self.orgs[row["id"]] = row
            return row
        msg = f"the fake doesn't insert into {table} through the SQL reader"
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
        elif table == "organizations":
            self._check_org(row)
        elif table == "login_throttle":
            if original is not None:
                for column in ("scope", "subject"):
                    assert row[column] == original[column], (
                        f"the key of a login_throttle row never changes ({column})"
                    )
            self._check_throttle(row, original)
        elif table in _SETTINGS_TABLES:
            self.check_settings(table, row, original=original)
        else:
            msg = f"the fake's SQL reader never writes {table}"
            raise AssertionError(msg)

    def _check_throttle(
        self, row: dict[str, Any], original: dict[str, Any] | None, *, check_key: bool = True
    ) -> None:
        """Migration 0012's login_throttle constraints, all of them on every written row."""
        for column in ("scope", "subject", "failures", "window_started_at", "expires_at"):
            if row[column] is None:
                msg = f'null value in column "{column}" of relation "login_throttle"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        if not isinstance(row["scope"], str):
            msg = "invalid input for query argument (scope): str expected"
            raise asyncpg.exceptions.DataError(msg)
        if not isinstance(row["subject"], bytes):
            msg = "invalid input for query argument (subject): bytes expected"
            raise asyncpg.exceptions.DataError(msg)
        if type(row["failures"]) is not int:
            msg = "invalid input for query argument (failures): int expected"
            raise asyncpg.exceptions.DataError(msg)
        for column in ("window_started_at", "locked_until", "expires_at"):
            value = row[column]
            if value is not None and (not isinstance(value, datetime) or value.tzinfo is None):
                # asyncpg reads a naive datetime as local time: refuse it here.
                msg = f"invalid input for query argument ({column}): an aware datetime expected"
                raise asyncpg.exceptions.DataError(msg)
        rules = (
            ("scope", row["scope"] in {"account", "ip"}),
            ("subject", len(row["subject"]) == 32),
            ("failures", row["failures"] >= 0),
            ("window", row["expires_at"] > row["window_started_at"]),
            (
                "lock",
                row["locked_until"] is None or row["expires_at"] >= row["locked_until"],
            ),
        )
        for name, valid in rules:
            if not valid:
                msg = f'new row for relation "login_throttle" violates the {name} check'
                raise asyncpg.exceptions.CheckViolationError(msg)
        if not check_key:
            return
        for other in self.throttle:
            if other is not original and (other["scope"], other["subject"]) == (
                row["scope"],
                row["subject"],
            ):
                msg = 'duplicate key value violates unique constraint "login_throttle_pkey"'
                raise asyncpg.exceptions.UniqueViolationError(msg)

    def _check_org(self, row: dict[str, Any]) -> None:
        """Migration 0004's organizations constraints, all of them on every written row."""
        for column in (
            "id",
            "name",
            "status",
            "seats",
            "monthly_budget_chf",
            "storage_quota_bytes",
            "data_residency",
            "default_response_language",
            "created_at",
            "updated_at",
        ):
            if row[column] is None:
                msg = f'null value in column "{column}" of relation "organizations"'
                raise asyncpg.exceptions.NotNullViolationError(msg)
        pending = row["status"] == "pending_deletion"
        rules = (
            ("name", 1 <= len(row["name"]) <= 120),
            ("status", row["status"] in _ORG_STATUSES),
            ("seats", 1 <= row["seats"] <= 100000),
            ("monthly_budget_chf", row["monthly_budget_chf"] >= 0),
            ("storage_quota_bytes", row["storage_quota_bytes"] >= 0),
            ("default_response_language", row["default_response_language"] in _RESPONSE_LANGUAGES),
            ("pending_deletion", pending == (row["purge_after"] is not None)),
            (
                "deletion_dates",
                (row["deletion_requested_at"] is None) == (row["purge_after"] is None),
            ),
        )
        for name, valid in rules:
            if not valid:
                msg = f'new row for relation "organizations" violates the {name} check'
                raise asyncpg.exceptions.CheckViolationError(msg)

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
        for column in ("email", "kind", "status", "ui_language", "personal_instructions"):
            if column in changed and row.get(column) is None:
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
            ("response_language", row.get("response_language") in {None, *_RESPONSE_LANGUAGES}),
            # GH-166 (migration 0021): an IANA-shaped name of at most 64 characters, or
            # NULL until the browser presets it; instructions of at most 1500 characters.
            ("timezone", _valid_timezone_column(row.get("timezone"))),
            (
                "personal_instructions",
                isinstance(row.get("personal_instructions"), str)
                and len(row["personal_instructions"]) <= 1500,
            ),
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

    def check_delete(self, table: str, row: dict[str, Any]) -> None:
        """ON DELETE RESTRICT: an org still referenced by a users or audit row stays."""
        if table != "organizations":
            return
        org_id = row["id"]
        referenced = any(user["org_id"] == org_id for user in self.users.values()) or any(
            event["org_id"] is not None and _canonical(event["org_id"]) == org_id
            for event in self.audit
        )
        if referenced:
            msg = 'update or delete on table "organizations" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)

    def delete_row(self, table: str, row: dict[str, Any]) -> None:
        """Delete one users, invitations, organizations, login_throttle or settings row; a
        user's rows and an org's org_settings row cascade (ON DELETE CASCADE). Call
        ``check_delete`` first."""
        if table == "login_throttle":
            self.throttle = [other for other in self.throttle if other is not row]
            return
        if table == "invitations":
            del self.invitations[row["id"]]
            return
        if table == "organizations":
            del self.orgs[row["id"]]
            # GH-159: org_settings.org_id REFERENCES organizations ON DELETE CASCADE.
            self.org_settings.pop(row["id"], None)
            # GH-161: permissions.org_id REFERENCES organizations ON DELETE CASCADE.
            self.permissions = {
                key: value for key, value in self.permissions.items() if key[0] != row["id"]
            }
            # GH-162: oauth_tokens.org_id and memory.org_id cascade too.
            self.oauth_tokens = {
                key: value
                for key, value in self.oauth_tokens.items()
                if value["org_id"] != row["id"]
            }
            self.memory = {
                key: value for key, value in self.memory.items() if value["org_id"] != row["id"]
            }
            return
        if table == "platform_settings":
            self.platform_settings = [other for other in self.platform_settings if other is not row]
            return
        if table == "org_settings":
            del self.org_settings[row["org_id"]]
            return
        if table == "user_settings":
            del self.user_settings[row["user_id"]]
            return
        if table == "permissions":
            del self.permissions[(row["org_id"], row["tool"], row["action"])]
            return
        if table == "oauth_tokens":
            del self.oauth_tokens[(row["user_id"], row["provider"])]
            return
        if table == "memory":
            del self.memory[(row["user_id"], row["key"])]
            return
        assert table == "users", f"the fake never deletes from {table}"
        user_id = row["id"]
        del self.users[user_id]
        # GH-159: user_settings.user_id REFERENCES users ON DELETE CASCADE.
        self.user_settings.pop(user_id, None)
        # GH-162: oauth_tokens.user_id and memory.user_id cascade too.
        self.oauth_tokens = {
            key: value for key, value in self.oauth_tokens.items() if key[0] != user_id
        }
        self.memory = {key: value for key, value in self.memory.items() if key[0] != user_id}
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
        values = insert_values(n, args)
        assert "id" not in values and "occurred_at" not in values, "no backdating"
        row: dict[str, Any] = {"id": uuid.uuid4(), "occurred_at": datetime.now(UTC)}
        row.update(values)
        row["target_ids"] = json.loads(row["target_ids"])
        row["metadata"] = json.loads(row["metadata"])
        row["ip"] = None if row["ip"] is None else str(row["ip"])
        if self.fail_audit_when is not None and self.fail_audit_when(row):
            raise AuditWriteError("the audit write was refused")
        org_id = row.get("org_id")
        if org_id is not None and _canonical(org_id) not in self.orgs:
            msg = 'insert or update on table "audit_events" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        self.audit.append(row)
        return "INSERT 0 1"

    def _purge_org_audit_events(
        self, method: str, match: re.Match[str], args: tuple[Any, ...]
    ) -> Any:
        """purge_org_audit_events(uuid) (migrations 0011, 0019): only for a due, pending
        org whose users are gone; deletes its audit rows, then the org row."""
        index = int(match.group(1)) - 1
        assert 0 <= index < len(args), "purge_org_audit_events needs its org id bound"
        raw = args[index]
        org_id = uuid.UUID(raw) if isinstance(raw, str) else raw
        assert isinstance(org_id, uuid.UUID), "purge_org_audit_events takes a uuid"
        org = self.orgs.get(_canonical(org_id))
        now = datetime.now(UTC)
        if (
            org is None
            or org["status"] != "pending_deletion"
            or org["purge_after"] is None
            or not org["purge_after"] <= now
        ):
            msg = "audit events can only be purged for an organization due for deletion"
            raise asyncpg.exceptions.InsufficientPrivilegeError(msg)
        # GH-220 (migration 0019): the function deletes the org row after its audit
        # rows, in the same statement; users.org_id is ON DELETE RESTRICT, so a
        # remaining user fails the whole call before anything changes.
        if any(user["org_id"] == org["id"] for user in self.users.values()):
            msg = 'update or delete on table "organizations" violates foreign key constraint'
            raise asyncpg.exceptions.ForeignKeyViolationError(msg)
        kept = [
            event
            for event in self.audit
            if event["org_id"] is None or _canonical(event["org_id"]) != _canonical(org_id)
        ]
        purged = len(self.audit) - len(kept)
        self.audit = kept
        self.delete_row("organizations", org)
        key = match.group(2) or "purge_org_audit_events"
        if method == "fetchval":
            return purged
        if method == "fetchrow":
            return {key: purged}
        if method == "fetch":
            return [{key: purged}]
        return "SELECT 1"

    def _enqueue(self, args: tuple[Any, ...]) -> Any:
        # email_outbox.enqueue_email binds (user_id, template_key, params_json).
        user_id, template_key, params_json = args
        account = self.users.get(plain(user_id))
        if account is None or account["deleted_at"] is not None:
            return None
        self.outbox.append(
            {
                "user_id": plain(user_id),
                # Copied from the users row when queued, as the real INSERT ... SELECT does.
                "recipient_address": account["email"],
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

    def _delete_user_token(self, method: str, n: str, args: tuple[Any, ...]) -> Any:
        """GH-164: ``DELETE FROM password_reset_tokens WHERE user_id = $n`` (an email
        change cancels the user's live reset link). Only that shape is accepted."""
        assert _DELETE_USER_TOKEN_RE.fullmatch(n), f"unexpected reset-token delete: {n}"
        user_id = plain(_bound(args, USER_ID_PARAM_RE, _where(n)))
        deleted = self.tokens.pop(user_id, None) is not None
        if method == "fetchval":
            return _pg(user_id) if deleted and " returning " in n else None
        return f"DELETE {int(deleted)}"

    def _last_admin_guard_rows(self, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        """``accounts.ensure_not_last_active_admin``'s query (GH-145, used by GH-164).

        The target's row (only when it belongs to the org) plus the org's active,
        non-deleted Org Admins, each flagged ``is_active_admin``, in id order. The
        FOR UPDATE lock is recorded in ``calls`` and has no other effect.
        """
        org_id, user_id = (_canonical(arg) for arg in args)

        def is_active_admin(account: dict[str, Any]) -> bool:
            return (
                account["role"] == "org_admin"
                and account["status"] == "active"
                and account["deleted_at"] is None
            )

        rows = [
            account
            for account in self.users.values()
            if account["org_id"] is not None
            and account["org_id"] == org_id
            and (account["id"] == user_id or is_active_admin(account))
        ]
        rows.sort(key=lambda account: account["id"])
        return [
            {"id": _pg(account["id"]), "is_active_admin": is_active_admin(account)}
            for account in rows
        ]

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

    def _apply_super_admin_policy(self, match: re.Match[str], args: tuple[Any, ...]) -> str:
        """GH-160: every Super Admin session takes a new idle timeout and expiry.

        ``expires_at = created_at + <lifetime hours>``. Migration 0009's CHECKs
        run on every changed row before any row changes (one statement: all or
        nothing); members' sessions are never touched.
        """
        rows = [
            row
            for row in self.sessions.values()
            if self.users.get(row["user_id"], {}).get("kind") == "super_admin"
        ]
        return self._retime_sessions(rows, match, args)

    def _apply_org_policy(self, match: re.Match[str], args: tuple[Any, ...]) -> str:
        """GH-169: every LIVE session of every user of one org takes a new idle timeout
        and expiry.

        The org is the bound ``$n`` of ``WHERE user_id IN (SELECT id FROM users
        WHERE org_id = $n)``: every user of that org whatever its role, status or
        deleted_at, never another org's user and never a Super Admin (whose
        org_id is NULL). The two live predicates (``expires_at > now()`` and
        ``last_seen_at + idle_timeout_minutes > now()``) are read against the OLD
        row values, the boundary resolve_session and the purge use: a session
        that had already ended (expired, or idle past its old timeout) but isn't
        purged yet is neither changed nor counted, so a longer policy never
        revives it. Same CHECKs (on the changed rows only) and all-or-nothing as
        the Super Admin form; answers ``UPDATE <live rows of the org>``.
        """
        org = args[int(match["org"]) - 1]
        if isinstance(org, str):
            try:
                org = uuid.UUID(org)
            except ValueError:
                msg = "invalid input for query argument: uuid expected"
                raise asyncpg.exceptions.DataError(msg) from None
        if not isinstance(org, uuid.UUID):
            msg = "invalid input for query argument: uuid expected"
            raise asyncpg.exceptions.DataError(msg)
        now = datetime.now(UTC)
        rows = [
            row
            for row in self.sessions.values()
            if (owner := self.users.get(row["user_id"])) is not None
            and owner.get("org_id") is not None
            and _canonical(owner["org_id"]) == _canonical(org)
            and row["expires_at"] > now
            and row["last_seen_at"] + timedelta(minutes=row["idle_timeout_minutes"]) > now
        ]
        return self._retime_sessions(rows, match, args)

    def _retime_sessions(
        self, rows: list[dict[str, Any]], match: re.Match[str], args: tuple[Any, ...]
    ) -> str:
        """Set ``idle_timeout_minutes`` and ``expires_at = created_at + hours`` on rows.

        Both bound values must be ints (DataError); migration 0009's CHECKs run
        on every row before any row changes (CheckViolationError, nothing
        changed). Answers ``UPDATE <count>``.
        """
        idle = args[int(match["idle"]) - 1]
        hours = args[int(match["hours"]) - 1]
        if type(idle) is not int or type(hours) is not int:
            msg = "invalid input for query argument: int expected"
            raise asyncpg.exceptions.DataError(msg)
        for row in rows:
            if not 15 <= idle <= 480:
                msg = "sessions idle_timeout_minutes check"
                raise asyncpg.exceptions.CheckViolationError(msg)
            expires_at = row["created_at"] + timedelta(hours=hours)
            if not row["created_at"] < expires_at <= row["created_at"] + _MAX_LIFETIME:
                msg = "sessions expiry check"
                raise asyncpg.exceptions.CheckViolationError(msg)
        for row in rows:
            row["idle_timeout_minutes"] = idle
            row["expires_at"] = row["created_at"] + timedelta(hours=hours)
        return f"UPDATE {len(rows)}"

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

    def _session_row(self, n: str, args: tuple[Any, ...]) -> dict[str, Any] | None:
        """The resolve row of a session, looked up by token hash or (GH-162) by session id."""
        token_hash = next((arg for arg in args if isinstance(arg, bytes)), None)
        session = self.sessions.get(token_hash) if token_hash is not None else None
        if token_hash is None and re.search(r"where s\.id = \$1$", n) and args:
            # GH-162: sessions.resolve_session_by_id (the OAuth callback).
            wanted = _canonical(args[0]) if isinstance(args[0], uuid.UUID) else None
            session = next(
                (row for row in self.sessions.values() if row["session_id"] == wanted), None
            )
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
            # GH-166: a single selected users column (e.g. "SELECT email FROM users ...").
            selected = re.match(r"select (?:\w+\.)?(\w+) from users\b", n)
            if selected is not None and selected.group(1) in _USER_COLUMNS - {"id"}:
                return account[selected.group(1)]
            return _pg(account["id"])
        return {
            "id": _pg(account["id"]),
            "kind": account["kind"],
            "org_id": _pg(account["org_id"]),
            "role": account["role"],
            "status": account["status"],
            "deleted_at": account["deleted_at"],
            # GH-161: the password re-auth of a critical promotion reads these.
            "email": account["email"],
            "password_hash": account["password_hash"],
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


def _masked_literals(text: str) -> str:
    """Blank out the contents of quoted literals (same length); parentheses stay."""
    out: list[str] = []
    quoted = False
    for char in text:
        if char == "'":
            quoted = not quoted
            out.append(char)
        else:
            out.append(" " if quoted else char)
    return "".join(out)


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


def _binary_split(text: str) -> tuple[str, str, str] | None:
    """Split ``a + b`` / ``a - b`` at its last top-level operator (left-associative).

    A ``-`` counts as binary only after an operand (not a leading sign); operators
    inside parentheses or literals don't count. None when there is no such operator.
    """
    masked = _masked(text)
    position = None
    for index, char in enumerate(masked):
        if char not in "+-" or index == 0:
            continue
        before = masked[:index].rstrip()
        if before and (before[-1].isalnum() or before[-1] in ")_'"):
            position = index
    if position is None:
        return None
    return text[:position].strip(), masked[position], text[position + 1 :].strip()


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


def _runs_on_reader(method: str, n: str, args: tuple[Any, ...]) -> bool:
    """True for the statements the SQL reader runs (see the module docstring)."""
    if re.search(r"\binvitations\b", n) or re.search(r"\blogin_throttle\b", n):
        return True
    if re.search(r"\b(?:platform|org|user)_settings\b", n) or re.search(r"\bpermissions\b", n):
        # GH-159: the settings scopes of migration 0013; GH-161: the org permission matrix.
        return True
    if re.search(r"\boauth_tokens\b", n) or re.search(r"\bmemory\b", n):
        # GH-162: the per-user connections and notes of migration 0017.
        return True
    table = _primary_table(n)
    if table is None and n.startswith("select") and re.search(r"\bsha256 ?\(", n):
        # GH-157: a FROM-less digest, e.g. the account subject of a typed email.
        return True
    if table == "organizations":
        return True
    if table == "audit_events":
        return n.startswith("select")
    if table != "users":
        return False
    if re.match(r"(?:insert into|update|delete from) users\b", n):
        return True
    if re.match(r"select exists\b", n) or method == "fetch":
        return True
    if re.search(r"\b(?:timezone|personal_instructions)\b", n.split(" from ", 1)[0]):
        # GH-166: a read of the account self-service columns runs on the reader, so
        # every selected column and predicate (deleted_at) applies.
        return True
    where = _where(n)
    if re.search(ORG_ID_PARAM_RE, where) is None:
        return False
    # GH-164: a lookup by id within an org (the Org Admin user routes) runs on the
    # reader too, so every predicate it states (status, deleted_at) and every
    # column it selects apply.
    return method == "fetch" or not any(isinstance(arg, str) for arg in args)


@dataclass(frozen=True)
class _Conflict:
    """An ON CONFLICT clause: DO NOTHING (no assignments) or DO UPDATE SET ... [WHERE]."""

    assignments: tuple[tuple[str, str], ...] | None
    where: str | None


def _on_conflict(table: str, text: str | None) -> _Conflict | None:
    """Read the ON CONFLICT clause of an INSERT into a settings table (None: no clause).

    The conflict target, when given, must be the table's primary key
    (InvalidColumnReferenceError otherwise, as in PostgreSQL); DO UPDATE needs one.
    """
    if text is None:
        return None
    match = re.match(r"(?:\( ?([\w ,]+?) ?\) ?)?do (nothing$|update set )", text)
    assert match is not None, f"the fake can't read ON CONFLICT {text!r}"
    if match.group(1) is not None:
        target = {column.strip() for column in match.group(1).split(",")}
        if target != set(_CONFLICT_KEYS[table]):
            msg = "no unique or exclusion constraint matches the ON CONFLICT specification"
            raise asyncpg.exceptions.InvalidColumnReferenceError(msg)
    if match.group(2) == "nothing":
        return _Conflict(assignments=None, where=None)
    assert match.group(1) is not None, "ON CONFLICT DO UPDATE needs a conflict target"
    parts = _top_split(text[match.end() :], r" where ")
    assert len(parts) <= 2, text
    assignments = []
    for piece in _top_split(parts[0], ","):
        assignment = re.fullmatch(r"(\w+) ?= ?(.+)", piece)
        assert assignment is not None, f"the fake can't read SET {piece}"
        column, expr = assignment.groups()
        if column not in _COLUMNS[table]:
            msg = f'column "{column}" of relation "{table}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        assignments.append((column, expr))
    return _Conflict(assignments=tuple(assignments), where=parts[1] if len(parts) == 2 else None)


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
        if match := re.fullmatch(r"case when (.+?) then (.+?) else (.+?) end", _masked(expr)):
            # GH-166: one WHEN branch; the condition is a boolean bind parameter or a
            # predicate the reader evaluates (a NULL condition takes the ELSE branch).
            condition = expr[match.start(1) : match.end(1)]
            if re.fullmatch(r"\$\d+(?: ?:: ?\w+)?", condition):
                flag = self.value(condition, ctx)
                assert flag is None or type(flag) is bool, f"CASE WHEN needs a boolean: {expr}"
                taken = flag is True
            else:
                taken = self.atom(condition, ctx)
            branch = match.group(2) if taken else match.group(3)
            start = match.start(2) if taken else match.start(3)
            return self.value(expr[start : start + len(branch)], ctx)
        if match := re.fullmatch(
            r"(?:interval ?'(\d+) ?([a-z]+?)s?'|'(\d+) ?([a-z]+?)s?' ?:: ?interval)", expr
        ):
            amount = int(match.group(1) or match.group(3))
            unit = _INTERVAL_UNITS.get(match.group(2) or match.group(4))
            assert unit is not None, f"the fake can't read the interval {expr!r}"
            return timedelta(**{unit: amount})
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
        if match := re.fullmatch(
            rf"{NOW_SQL} ?\+ ?make_interval ?\( ?(days|hours|mins|secs) ?=> ?\$(\d+)"
            r"(?: ?:: ?\w+)? ?\)",
            expr,
        ):
            amount = self._arg(match.group(2))
            assert isinstance(amount, int | float) and not isinstance(amount, bool), amount
            unit = {"days": "days", "hours": "hours", "mins": "minutes", "secs": "seconds"}
            return self.now + timedelta(**{unit[match.group(1)]: amount})
        if match := re.fullmatch(
            r"make_interval ?\( ?(days|hours|mins|secs) ?=> ?(.+?) ?\)(?: ?:: ?interval)?", expr
        ):
            amount = self.value(match.group(2), ctx)
            assert isinstance(amount, int | float) and not isinstance(amount, bool), amount
            unit = {"days": "days", "hours": "hours", "mins": "minutes", "secs": "seconds"}
            return timedelta(**{unit[match.group(1)]: amount})
        if (binary := _binary_split(expr)) is not None:
            left_text, operator, right_text = binary
            left, right = self.value(left_text, ctx), self.value(right_text, ctx)
            if left is None or right is None:
                return None
            return left + right if operator == "+" else left - right
        if match := re.fullmatch(r"coalesce ?\((.+)\)", expr):
            # Every argument is resolved (PostgreSQL resolves column references when it
            # parses the statement), then the first non-NULL one wins.
            values = [self.value(item, ctx) for item in _top_split(match.group(1), ",")]
            return next((value for value in values if value is not None), None)
        if match := re.fullmatch(r"(greatest|least) ?\((.+)\)", expr):
            # Like PostgreSQL, NULL arguments are ignored.
            present = [
                value
                for item in _top_split(match.group(2), ",")
                if (value := self.value(item, ctx)) is not None
            ]
            if not present:
                return None
            return max(present) if match.group(1) == "greatest" else min(present)
        if match := re.fullmatch(r"lower ?\((.+)\)", expr):
            inner = self.value(match.group(1), ctx)
            return inner.lower() if isinstance(inner, str) else inner
        if match := re.fullmatch(r"convert_to ?\((.+)\)", expr):
            items = _top_split(match.group(1), ",")
            assert len(items) == 2, f"convert_to takes a text and an encoding: {expr!r}"
            encoding = self.value(items[1], ctx)
            assert isinstance(encoding, str), expr
            assert re.sub(r"[^a-z0-9]", "", encoding.lower()) == "utf8", (
                f"the fake converts to UTF8 only: {expr!r}"
            )
            text = self.value(items[0], ctx)
            if text is None:
                return None
            assert isinstance(text, str), f"convert_to needs a text value: {expr!r}"
            return text.encode("utf-8")
        if match := re.fullmatch(r"sha256 ?\((.+)\)", expr):
            data = self.value(match.group(1), ctx)
            if data is None:
                return None
            if not isinstance(data, bytes | bytearray):
                msg = "function sha256(text) does not exist"
                raise asyncpg.exceptions.UndefinedFunctionError(msg)
            return hashlib.sha256(bytes(data)).digest()
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
        if match := re.fullmatch(r"(.+?) is (not )?(true|false)", masked):
            # GH-159: e.g. "WHERE id IS TRUE" on platform_settings.
            value = self.value(atom[: match.end(1)], ctx)
            assert value is None or type(value) is bool, f"IS TRUE needs a boolean: {atom}"
            holds = value is (match.group(3) == "true")
            return holds != bool(match.group(2))
        if re.fullmatch(r"(?:\w+\.)?\w+", masked):
            # GH-159: a bare boolean column ("WHERE id") or literal.
            value = self.value(atom, ctx)
            assert value is None or type(value) is bool, f"not a boolean predicate: {atom}"
            return value is True
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
            if _AGGREGATE_RE.search(_masked_literals(expr)):
                name = re.match(r"(?:coalesce ?\( ?)?(\w+)", expr)
                assert name is not None, expr
                items.append(("aggregate", alias or name.group(1), expr))
            elif re.fullmatch(r"(?:\w+\.)?\w+", expr) and not re.fullmatch(r"-?\d+|null", expr):
                items.append(("value", alias or expr.rsplit(".", 1)[-1], expr))
            elif re.search(r"<>|!=|<=|>=|=|<|>| is (?:not )?null$", _masked(expr)):
                items.append(("predicate", alias or "?column?", expr))
            else:
                items.append(("value", alias or "?column?", expr))
        if any(kind == "aggregate" for kind, _, _ in items):
            # One row over every context (no GROUP BY in the fake).
            assert all(kind == "aggregate" for kind, _, _ in items), "no GROUP BY in the fake"
            return [{key: self.aggregate(expr, contexts) for _, key, expr in items}]
        rows = []
        for ctx in contexts:
            row: dict[str, Any] = {}
            for kind, key, expr in items:
                value = self.atom(expr, ctx) if kind == "predicate" else self.value(expr, ctx)
                row[key] = _pg(value) if isinstance(value, uuid.UUID) else value
            rows.append(row)
        return rows

    def aggregate(self, expr: str, contexts: list[_Context]) -> Any:
        """Evaluate an aggregate expression over every row context, as PostgreSQL would.

        ``count(*)`` / ``count(1)`` / ``count(col)``; ``bool_and`` / ``every`` /
        ``bool_or`` (NULL over no non-NULL input); ``coalesce(...)`` of aggregates
        and constants; an optional trailing cast is ignored.
        """
        expr = _unwrap(expr)
        cast = re.fullmatch(r"(.+?) ?:: ?\w+", _masked(expr))
        if cast is not None:
            return self.aggregate(expr[: cast.end(1)], contexts)
        if match := re.fullmatch(r"count ?\((\*|1|.+)\)", expr):
            inner = match.group(1).strip()
            if inner in {"*", "1"}:
                return len(contexts)
            return sum(1 for ctx in contexts if self.value(inner, ctx) is not None)
        if match := re.fullmatch(r"(bool_and|every|bool_or) ?\((.+)\)", expr):
            values = [self.value(match.group(2), ctx) for ctx in contexts]
            present = [value for value in values if value is not None]
            assert all(type(value) is bool for value in present), f"{match.group(1)} of non-bools"
            if not present:
                return None
            return any(present) if match.group(1) == "bool_or" else all(present)
        if match := re.fullmatch(r"coalesce ?\((.+)\)", expr):
            for item in _top_split(match.group(1), ","):
                value = self.aggregate(item, contexts)
                if value is not None:
                    return value
            return None
        assert not _AGGREGATE_RE.search(_masked_literals(expr)), f"the fake can't read {expr!r}"
        return self.value(expr, {})

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
        if "from" not in clauses:
            # GH-157: a FROM-less SELECT (a computed digest) is one row of values.
            assert set(clauses) == {"select"}, f"a SELECT without FROM: {n}"
            return self.project(clauses["select"], [{}])
        assert not clauses["select"].startswith("distinct"), "no DISTINCT in the fake"
        if ("for update" in clauses or "for no key update" in clauses) and _AGGREGATE_RE.search(
            _masked_literals(clauses["select"])
        ):
            msg = "FOR UPDATE is not allowed with aggregate functions"
            raise asyncpg.exceptions.FeatureNotSupportedError(msg)
        contexts = self.filtered(self.contexts(_sources(clauses["from"])), clauses.get("where"))
        if "order by" in clauses:
            contexts = self.ordered(contexts, clauses["order by"])
        rows = self.project(clauses["select"], contexts)
        if "limit" in clauses:
            rows = rows[: int(self.value(clauses["limit"], {}))]
        return rows

    def insert(self, n: str) -> tuple[list[dict[str, Any]], int]:
        if re.search(
            r"\b(?:(?:platform|org|user)_settings|permissions|oauth_tokens|memory)\b",
            n.split("(", 1)[0],
        ):
            return self.insert_settings(n)
        clauses = _clauses(n, ("insert into", "values", "on conflict", "returning"))
        head = re.fullmatch(r"(\w+) ?\((.*)\)", clauses["insert into"])
        values = clauses.get("values", "")
        assert head is not None and _unwrap(values) != values, f"one VALUES row only: {n}"
        table = head.group(1)
        skip_conflict = False
        if "on conflict" in clauses:
            # GH-157: only login_throttle's ON CONFLICT (scope, subject) DO NOTHING.
            assert table == "login_throttle" and re.fullmatch(
                r"(?:\( ?(?:scope ?, ?subject|subject ?, ?scope) ?\) ?)?do nothing",
                clauses["on conflict"],
            ), f"the fake doesn't do this ON CONFLICT: {n}"
            skip_conflict = True
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
        row = self.db.new_row(table, given, self.now, skip_conflict=skip_conflict)
        if row is None:
            return [], 0
        ctx: _Context = {table: (table, row)}
        returned = self.project(clauses["returning"], [ctx]) if "returning" in clauses else []
        return returned, 1

    def insert_settings(self, n: str) -> tuple[list[dict[str, Any]], int]:
        """An INSERT into a settings table of migration 0013 (see the module docstring)."""
        clauses = _clauses(n, ("insert into", "values", "select", "on conflict", "returning"))
        head = re.fullmatch(r"(\w+)(?: as (\w+))? ?\((.*)\)", clauses["insert into"])
        assert head is not None, f"the fake can't read this INSERT: {n}"
        table, alias = head.group(1), head.group(2) or head.group(1)
        assert table in _SETTINGS_TABLES, n
        columns = [column.strip().strip('"') for column in head.group(3).split(",")]
        unknown = set(columns) - _COLUMNS[table]
        if unknown:
            msg = f'column "{sorted(unknown)[0]}" of relation "{table}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        candidates: list[dict[str, Any]] = []
        if "values" in clauses:
            values = clauses["values"]
            assert "select" not in clauses and _unwrap(values) != values, f"one VALUES row: {n}"
            exprs = _top_split(values[1:-1], ",")
            assert len(columns) == len(exprs), n
            candidates.append(
                {
                    column: _store(self.value(expr, {}))
                    for column, expr in zip(columns, exprs, strict=True)
                    if expr != "default"
                }
            )
        else:
            assert "select" in clauses, f"no rows to add: {n}"
            for selected in self.select("select " + clauses["select"]):
                row_values = list(selected.values())
                assert len(row_values) == len(columns), n
                candidates.append(
                    {
                        column: _store(value)
                        for column, value in zip(columns, row_values, strict=True)
                    }
                )
        conflict = _on_conflict(table, clauses.get("on conflict"))
        returned: list[dict[str, Any]] = []
        count = 0
        for given in candidates:
            row = self.db.settings_defaults(table, given, self.now)
            # The proposed row's CHECKs run before the conflict check, as in PostgreSQL.
            self.db.check_settings(table, row, original=None, keys=False)
            existing = self.db.settings_by_key(table, row)
            if existing is None:
                self.db.check_settings(table, row, original=None)
                self.db.store_settings(table, row)
                target = row
            elif conflict is None:
                msg = f'duplicate key value violates unique constraint "{table}_pkey"'
                raise asyncpg.exceptions.UniqueViolationError(msg)
            elif conflict.assignments is None:
                continue
            else:
                ctx: _Context = {alias: (table, existing), "excluded": (table, row)}
                if conflict.where is not None and not self.holds(conflict.where, ctx):
                    continue
                new = {
                    column: _store(self.value(expr, ctx)) for column, expr in conflict.assignments
                }
                if set(new) & {"org_id", "user_id", "id", *_CONFLICT_KEYS[table]}:
                    msg = "the fake never changes a settings row's key"
                    raise AssertionError(msg)
                self.db.check_settings(table, {**existing, **new}, original=existing)
                existing.update(new)
                target = existing
            count += 1
            if "returning" in clauses:
                returned.extend(self.project(clauses["returning"], [{alias: (table, target)}]))
        return returned, count

    def update(self, n: str) -> tuple[list[dict[str, Any]], int]:
        clauses = _clauses(n, ("update", "set", "from", "where", "returning"))
        head = re.fullmatch(r"(?:only )?(\w+)(?: (?:as )?(\w+))?", clauses["update"])
        assert head is not None, n
        table, alias = head.group(1), head.group(2) or head.group(1)
        assert table in _WRITABLE, f"the fake never updates {table}"
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
            targets.append((ctx, row, self.db.normalized(table, new)))
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
        assert table in _WRITABLE, f"the fake never deletes {table}"
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
            self.db.check_delete(table, row)
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
        self._db.open_transactions += 1
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
            self._db.open_transactions -= 1

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
