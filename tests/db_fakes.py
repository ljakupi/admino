"""Shared in-memory database for the service and HTTP tests (GH-151 to GH-176).

``FakeDb`` stands in for the users, organizations, invitations, sessions,
password_reset_tokens, email_outbox, audit_events, login_throttle,
platform_settings, org_settings, user_settings, permissions, oauth_tokens,
memory, chats and chat_messages tables behind a pool-shaped
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

Chats (GH-176, migration 0024; GH-266, migration 0025; GH-271, migration 0026):
- ``chats`` (``chats``, keyed by id): ``id`` (UUID primary key, default a new
  uuid4), ``org_id`` (UUID NOT NULL, references organizations ON DELETE
  CASCADE), ``owner_user_id`` (UUID NOT NULL; migration 0026: the composite
  foreign key ``CHAT_OWNER_FKEY`` (owner_user_id, org_id) references users (id,
  org_id) ON DELETE CASCADE, so the owner is a member of the chat's org:
  another org's member, a Super Admin (no org) or an unknown user is a
  ForeignKeyViolationError), ``title`` (TEXT NOT NULL, default '', CHECK
  ``char_length(title) <= 200``), ``title_source`` (TEXT NOT NULL, default
  'auto', auto / user),
  ``legacy_session_id`` (NULL or fully matching ``[a-zA-Z0-9_-]{1,64}``: no
  trailing newline), ``external_content`` (BOOLEAN NOT NULL, default false),
  ``created_at`` and ``last_activity_at`` (NOT NULL, default now()) and
  ``deleted_at`` (NULL: live; set: trashed); UNIQUE (id, org_id); the partial
  unique index ``chats_legacy_session_key`` on (owner_user_id,
  legacy_session_id) WHERE legacy_session_id IS NOT NULL AND deleted_at IS
  NULL (a trashed chat's session id can be used again).
- ``chat_messages`` (``chat_messages``, keyed by id, insertion order): ``id``
  (UUID primary key, default a new uuid4), ``seq`` (BIGINT GENERATED ALWAYS AS
  IDENTITY, UNIQUE: ``chat_seq`` is the fake-global sequence, strictly
  increasing and never reused; a failed or rolled-back insert leaves a gap, as
  the sequence is not part of a transaction's snapshot; an INSERT naming
  ``seq`` raises GeneratedAlwaysError), ``chat_id`` (UUID NOT NULL),
  ``org_id`` (UUID NOT NULL, references organizations ON DELETE CASCADE),
  ``role`` (TEXT NOT NULL: user / assistant / tool), ``content`` (TEXT NOT
  NULL, at most 65536 characters), ``tool_use_blocks`` (JSONB: NULL or a JSON
  array), ``tool_call_id`` (NULL or fully matching ``[a-zA-Z0-9_-]{1,128}``),
  ``tool_calls`` (JSONB: NULL or a JSON array of at most 50 items), ``status``
  (TEXT NOT NULL, default 'complete': complete / stopped / error /
  awaiting_confirmation / limit_reached) and ``created_at`` (NOT NULL, default
  now()); the composite foreign key (chat_id, org_id) references chats (id,
  org_id) ON DELETE CASCADE, so a message whose org differs from its chat's is
  refused.
- Checked like PostgreSQL, in its order, with asyncpg's exception classes:
  bind values through asyncpg's encoders (DataError: a non-bool
  external_content, a non-int, a non-str text or JSONB value, a naive
  datetime, a str that isn't a UUID, a lone surrogate; the text repeats the
  value's repr like asyncpg's), the server's input (a TEXT value holding
  U+0000: CharacterNotInRepertoireError "null character not permitted";
  invalid JSON: InvalidTextRepresentationError; the JSON escape ``\\u0000``:
  UntranslatableCharacterError "unsupported Unicode escape sequence"), NOT
  NULL (NotNullViolationError), the CHECKs by constraint name
  (CheckViolationError), the unique keys (UniqueViolationError) and the
  foreign keys (ForeignKeyViolationError). Errors carry ``table_name``,
  ``column_name`` / ``constraint_name`` and, like the driver's, a DETAIL in
  ``str(error)``: "Failing row contains (...)" for NOT NULL and CHECK (the
  row's content, each value cut to 64 bytes) and the key for the legacy
  session index (the session id): a log line that prints the error leaks
  what the real driver's would.
- Every statement naming either table runs on the SQL reader, after what
  asyncpg and PostgreSQL check first: the argument count (InterfaceError) and
  no gap in the ``$n`` numbering (IndeterminateDatatypeError); each parameter
  whose type the SQL implies (a cast, ``col <op> $n``, a row comparison, an
  INSERT position, ``LIMIT $n``) through its encoder; every str argument's
  U+0000 (used or not); and migration 0024's grants: admino_app may not
  DELETE chats nor UPDATE or DELETE chat_messages (InsufficientPrivilegeError;
  the cascades still run). JSONB values travel as JSON text (``$n::jsonb``,
  no codec, like ``oauth_tokens.scopes``): parsed on write, stored and
  returned as a JSON str, re-serialized with JSONB's key order (shorter keys
  first), so it may differ from the text sent; a list or dict bound directly
  is a DataError.
- Migration 0025 (GH-266): an UPDATE of chats may SET only title,
  title_source, last_activity_at, external_content and deleted_at
  (``CHAT_UPDATE_COLUMNS``); naming id, org_id, owner_user_id, created_at or
  legacy_session_id is InsufficientPrivilegeError "permission denied for table
  chats", raised before the statement runs (nothing changes), in a ``col =``
  piece and (GH-271) in a row-constructor piece ``(a, b) = (...)`` (a row,
  ``ROW(...)`` or a sub-select; reading one over allowed columns only stays
  unsupported, the app doesn't use the form). Its BEFORE
  UPDATE row trigger refuses turning a row's external_content from true to
  false: CheckViolationError ``CHAT_EXTERNAL_CONTENT_RESET`` ("chats.external_content
  can't be reset", SQLSTATE 23514, no row data), raised before the row's other
  checks; every target row is checked before any is written, so the statement
  changes no row. false -> true, true -> true and other columns of a flagged
  chat pass.
- Deleting a users row deletes the user's chats and their messages;
  deleting an organizations row (the reader's DELETE and the
  ``purge_org_audit_events`` emulation) deletes the org's chats and
  messages; deleting a chats row deletes its messages. ``conn.transaction()``
  snapshots and restores both tables.
- The SQL forms of contract §2 (S1 to S13) and the general reader features
  they need: ``INSERT INTO t (cols) VALUES (exprs) [RETURNING cols]`` (one
  row; ``$n`` optionally cast, literals, ``DEFAULT``, ``now()``); ``INSERT
  INTO t (cols) SELECT <columns, literals, $n> FROM ... [WHERE ...]`` (one
  row per selected row, all or nothing); ``SELECT cols | count(*) FROM t
  WHERE ... [ORDER BY a DESC, b DESC] [LIMIT $n]``; ``UPDATE t SET col =
  <$n | literal | now() | true>, ... WHERE ... [RETURNING cols]``. WHERE
  takes the reader's AND-ed predicates plus the row comparison ``(a, b) <
  ($n, $m)`` (lexicographic, NULL-aware, as PostgreSQL). LIMIT must bind an
  int (DataError otherwise; negative: InvalidRowCountInLimitClauseError;
  NULL: no limit). A SELECT on a chat table without ORDER BY answers its rows
  newest-first (PostgreSQL promises no order). Predicates the SQL doesn't
  state are not applied (a missing owner, org or ``deleted_at IS NULL``
  filter shows up), and anything else fails the test with an AssertionError.
- GH-24's S12b (contract §2: the org notice in every live chat of the org
  whose latest message isn't awaiting a confirmation) adds two reader
  features. ``a IS [NOT] DISTINCT FROM b`` is NULL-safe: NULL is distinct
  from any value and not from NULL. A scalar subquery ``(SELECT col FROM t a
  WHERE ... [ORDER BY ...] [LIMIT n])`` goes wherever a value goes; a
  correlated reference (``m.chat_id = c.id``) reads the enclosing row, a
  column resolving in the subquery's own FROM first, then in each enclosing
  query's, nearest first, as in PostgreSQL. It sees the tables as the
  statement found them: an INSERT ... SELECT builds every row before storing
  any (one new ``seq`` per row, in the chats' scan order). No row: NULL; more
  than one row: CardinalityViolationError; more than one column:
  PostgresSyntaxError.
- GH-244's send path (contract C3: T1, the turn setup over organizations,
  org_settings, users, chats and permissions; T2, a chat with its latest
  messages) adds three reader features. ``ARRAY[a, b, ...]`` builds a list
  (square brackets nest like parentheses for the reader). ``ARRAY(SELECT
  <one column> FROM ... WHERE ...)`` goes wherever a value goes: one element
  per row in the rows' order (a table without ORDER BY: its stored order;
  ``[]`` when nothing matches, never NULL), correlated like a scalar
  subquery; elements that are arrays give a list of lists, as asyncpg
  decodes a two-dimensional array (a NULL or empty one:
  NullValueNotAllowedError / ArraySubscriptError, and so are arrays of
  different lengths; more than one column: PostgresSyntaxError). A
  sub-select in FROM, ``[LEFT] JOIN [LATERAL] (SELECT ...) alias ON ...``
  (or after a comma, without ON; the alias is required): its select list
  names its columns (``alias.col``; an unknown one is UndefinedColumnError),
  a LATERAL one runs once per combination of the items before it and reads
  their columns (a non-LATERAL one runs once and can't: UndefinedTableError),
  and a LEFT JOIN without a row keeps the outer row once with every
  ``alias.*`` NULL; the outer ORDER BY may sort by any of its columns, selected
  or not (NULLs first descending). Several LEFT JOINs whose ON conditions mix
  bind parameters, outer columns and ``IS NULL`` work as before. Values come
  back as asyncpg's (asyncpg UUIDs, inside arrays too; JSONB as the JSON text
  stored). Both statements name chats, so they run on the reader after the
  chat-table bind checks (UUID parameters, a bigint ``LIMIT $n``).
- Helpers: ``add_chat(owner_user_id, *, org_id=None, chat_id=None, title='',
  title_source='auto', legacy_session_id=None, external_content=False,
  created_at=None, last_activity_at=None, deleted_at=None)`` (org_id: the
  owner's, another org refused by ``CHAT_OWNER_FKEY``; last_activity_at:
  created_at, itself now) and
  ``add_chat_message(chat_id, role, content, *, tool_use_blocks=None,
  tool_call_id=None, tool_calls=None, status='complete', created_at=None)``
  (org_id: the chat's; the next seq; the JSONB values as Python lists) seed
  rows checked like an INSERT and return their ids; ``chat_row(chat_id)``,
  ``chats_of(user_id)`` (any deletion state, by created_at then id) and
  ``messages_of(chat_id)`` (by seq, the JSONB columns as Python values) read
  copies back. ``add_account(user_id=...)`` gives an account a fixed id.

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

# GH-176: persisted, tenant-scoped chats (migration 0024). Column -> type, in the
# migration's column order (NOT NULL checks and "Failing row contains" follow it).
_CHAT_TYPES: Final[dict[str, dict[str, str]]] = {
    "chats": {
        "id": "uuid",
        "org_id": "uuid",
        "owner_user_id": "uuid",
        "title": "text",
        "title_source": "text",
        "legacy_session_id": "text",
        "external_content": "bool",
        "created_at": "timestamptz",
        "last_activity_at": "timestamptz",
        "deleted_at": "timestamptz",
    },
    "chat_messages": {
        "id": "uuid",
        "seq": "int",
        "chat_id": "uuid",
        "org_id": "uuid",
        "role": "text",
        "content": "text",
        "tool_use_blocks": "jsonb",
        "tool_call_id": "text",
        "tool_calls": "jsonb",
        "status": "text",
        "created_at": "timestamptz",
    },
}
_CHAT_NULLABLE: Final[dict[str, frozenset[str]]] = {
    "chats": frozenset({"legacy_session_id", "deleted_at"}),
    "chat_messages": frozenset({"tool_use_blocks", "tool_call_id", "tool_calls"}),
}
_CHAT_TABLES: Final = frozenset(_CHAT_TYPES)
# A statement that names either chat table (on the SQL with its literals blanked).
_CHAT_TABLE_RE: Final = re.compile(r"\b(?:chats|chat_messages)\b")
CHAT_TITLE_MAX: Final = 200
CHAT_CONTENT_MAX: Final = 65536
CHAT_TOOL_CALLS_MAX: Final = 50
CHAT_TITLE_SOURCES: Final = frozenset({"auto", "user"})
CHAT_ROLES: Final = frozenset({"user", "assistant", "tool"})
CHAT_MESSAGE_STATUSES: Final = frozenset(
    {"complete", "stopped", "error", "awaiting_confirmation", "limit_reached"}
)
# The two regex CHECKs, read the way PostgreSQL reads '^...$' (fullmatch: a trailing
# newline doesn't match).
LEGACY_SESSION_ID_RE: Final = re.compile(r"[a-zA-Z0-9_-]{1,64}")
TOOL_CALL_ID_RE: Final = re.compile(r"[a-zA-Z0-9_-]{1,128}")
# GH-266 (migration 0025): the only chats columns admino_app may UPDATE, and the
# message of the trigger that keeps external_content true once it is.
CHAT_UPDATE_COLUMNS: Final = frozenset(
    {"title", "title_source", "last_activity_at", "external_content", "deleted_at"}
)
CHAT_EXTERNAL_CONTENT_RESET: Final = "chats.external_content can't be reset"
# GH-271 (migration 0026): the composite foreign key (owner_user_id, org_id) ->
# users (id, org_id) that ties a chat's owner to the chat's org (the only chats ->
# users key: it replaced 0024's chats_owner_user_id_fkey).
CHAT_OWNER_FKEY: Final = "chats_owner_org_fkey"
# An UPDATE of chats (normalized SQL), whose SET 0025's column grant limits.
_CHATS_UPDATE_RE: Final = re.compile(r"update (?:only )?(?:public\.)?chats\b")
# What a ``$n::<type>`` cast tells about a bind parameter's type.
_CAST_TYPES: Final[dict[str, str]] = {
    "uuid": "uuid",
    "text": "text",
    "varchar": "text",
    "bool": "bool",
    "boolean": "bool",
    "int": "int",
    "int4": "int",
    "int8": "int",
    "integer": "int",
    "bigint": "int",
    "timestamptz": "timestamptz",
    "jsonb": "jsonb",
    "json": "jsonb",
}
_COMPARISON: Final = r"(?:<>|!=|<=|>=|=|<|>)"
# PostgreSQL truncates each value of a "Failing row contains (...)" detail to 64 bytes.
_FAILING_ROW_FIELD_MAX: Final = 64

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
    "chats": frozenset(_CHAT_TYPES["chats"]),
    "chat_messages": frozenset(_CHAT_TYPES["chat_messages"]),
}
# The tables the SQL reader writes (INSERT, UPDATE, DELETE).
_WRITABLE: Final = frozenset(
    {"users", "invitations", "organizations", "login_throttle", *_SETTINGS_TABLES, *_CHAT_TABLES}
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
        # GH-176: persisted chats and their messages, each keyed by id (insertion
        # order), and the identity sequence behind chat_messages.seq. The sequence
        # is not part of a transaction's snapshot: like PostgreSQL's, a rolled-back
        # or failed insert leaves a gap.
        self.chats: dict[uuid.UUID, dict[str, Any]] = {}
        self.chat_messages: dict[uuid.UUID, dict[str, Any]] = {}
        self.chat_seq = 0
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
        user_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        """Add an account and return its id (a plain uuid.UUID).

        A member's org is created (active, 100 seats) if it doesn't exist.
        ``org_status`` overrides the org's status for this account's login,
        session and reset lookups only; left out, the account follows the
        organizations row. ``created_at`` defaults to one day ago and
        ``last_login_at`` to None (GH-164: the Org Admin user list shows both).
        ``response_language`` (None: the org default), ``timezone`` (None:
        not preset yet) and ``personal_instructions`` ('' : none) are the
        account self-service columns (GH-166, migration 0021). ``user_id``
        (GH-176) gives the account a fixed id (e.g. ``auth_helpers.TEST_MEMBER_ID``)
        instead of a random one; it must not exist yet.
        """
        user_id = uuid.uuid4() if user_id is None else uuid.UUID(int=user_id.int)
        assert user_id not in self.users, f"an account with id {user_id} exists already"
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

    def add_chat(
        self,
        owner_user_id: uuid.UUID,
        *,
        org_id: uuid.UUID | None = None,
        chat_id: uuid.UUID | None = None,
        title: str = "",
        title_source: str = "auto",
        legacy_session_id: str | None = None,
        external_content: bool = False,
        created_at: datetime | None = None,
        last_activity_at: datetime | None = None,
        deleted_at: datetime | None = None,
    ) -> uuid.UUID:
        """Store a chats row (GH-176) as migrations 0024 to 0026 allow it; return its id.

        ``org_id`` defaults to the owner's org; an owner that doesn't exist, or
        (GH-271, migration 0026) isn't a member of ``org_id``'s org, is a
        ForeignKeyViolationError on ``CHAT_OWNER_FKEY``. ``chat_id`` defaults to
        a new uuid4, ``created_at`` to now and ``last_activity_at`` to
        ``created_at``. Every value is checked like an INSERT (DataError,
        CharacterNotInRepertoireError, NotNull, the CHECKs, the partial unique
        legacy session key, the foreign keys). Returns a plain uuid.UUID.
        """
        if org_id is None:
            owner = (
                self.users.get(uuid.UUID(int=owner_user_id.int))
                if isinstance(owner_user_id, uuid.UUID)
                else None
            )
            if owner is None:
                raise _pg_error(
                    asyncpg.exceptions.ForeignKeyViolationError,
                    'insert or update on table "chats" violates foreign key constraint'
                    f' "{CHAT_OWNER_FKEY}"',
                    table="chats",
                    constraint=CHAT_OWNER_FKEY,
                )
            org_id = owner["org_id"]
        now = datetime.now(UTC)
        created = created_at if created_at is not None else now
        given: dict[str, Any] = {
            "org_id": org_id,
            "owner_user_id": owner_user_id,
            "title": title,
            "title_source": title_source,
            "legacy_session_id": legacy_session_id,
            "external_content": external_content,
            "created_at": created,
            "last_activity_at": last_activity_at if last_activity_at is not None else created,
            "deleted_at": deleted_at,
        }
        if chat_id is not None:
            given["id"] = chat_id
        row = self.build_chat_row("chats", given, now)
        self.store_chat_row("chats", row)
        return uuid.UUID(int=row["id"].int)

    def add_chat_message(
        self,
        chat_id: uuid.UUID,
        role: str,
        content: str,
        *,
        tool_use_blocks: list[Any] | None = None,
        tool_call_id: str | None = None,
        tool_calls: list[Any] | None = None,
        status: str = "complete",
        created_at: datetime | None = None,
    ) -> uuid.UUID:
        """Store a chat_messages row (GH-176) as migration 0024 allows it; return its id.

        ``org_id`` is the chat's (a chat that doesn't exist is a
        ForeignKeyViolationError), ``seq`` the next identity value,
        ``created_at`` defaults to now. ``tool_use_blocks`` / ``tool_calls`` are
        Python values, sent as their JSON text like the app's ``$n::jsonb``
        (so a str holding U+0000 fails like the escape ``\\u0000``). Checked like
        an INSERT. The chat's ``last_activity_at`` is not touched (a seed).
        """
        chat = (
            self.chats.get(uuid.UUID(int=chat_id.int)) if isinstance(chat_id, uuid.UUID) else None
        )
        if chat is None:
            raise _pg_error(
                asyncpg.exceptions.ForeignKeyViolationError,
                'insert or update on table "chat_messages" violates foreign key constraint'
                ' "chat_messages_chat_fkey"',
                table="chat_messages",
                constraint="chat_messages_chat_fkey",
            )
        now = datetime.now(UTC)
        given: dict[str, Any] = {
            "chat_id": chat_id,
            "org_id": chat["org_id"],
            "role": role,
            "content": content,
            "tool_use_blocks": None if tool_use_blocks is None else json.dumps(tool_use_blocks),
            "tool_call_id": tool_call_id,
            "tool_calls": None if tool_calls is None else json.dumps(tool_calls),
            "status": status,
            "created_at": created_at if created_at is not None else now,
        }
        row = self.build_chat_row("chat_messages", given, now)
        self.store_chat_row("chat_messages", row)
        return uuid.UUID(int=row["id"].int)

    def chat_row(self, chat_id: uuid.UUID) -> dict[str, Any] | None:
        """A copy of a stored chats row (GH-176), None when there is none."""
        row = self.chats.get(uuid.UUID(int=chat_id.int))
        return dict(row) if row is not None else None

    def chats_of(self, user_id: uuid.UUID) -> list[dict[str, Any]]:
        """Copies of every chats row a user owns, trashed ones included, by created_at then id."""
        owner = uuid.UUID(int=user_id.int)
        rows = [dict(row) for row in self.chats.values() if row["owner_user_id"] == owner]
        return sorted(rows, key=lambda row: (row["created_at"], row["id"]))

    def messages_of(self, chat_id: uuid.UUID) -> list[dict[str, Any]]:
        """Copies of a chat's chat_messages rows by seq; the JSONB columns as Python values."""
        wanted = uuid.UUID(int=chat_id.int)
        rows = sorted(
            (row for row in self.chat_messages.values() if row["chat_id"] == wanted),
            key=lambda row: row["seq"],
        )
        return [
            {
                **row,
                **{
                    column: None if row[column] is None else json.loads(row[column])
                    for column in ("tool_use_blocks", "tool_calls")
                },
            }
            for row in rows
        ]

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
                "chats": self.chats,
                "chat_messages": self.chat_messages,
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
        self.chats = state["chats"]
        self.chat_messages = state["chat_messages"]

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
        if _CHAT_TABLE_RE.search(_masked_literals(n)):
            # GH-176: every statement naming chats or chat_messages runs on the reader,
            # after the checks asyncpg and PostgreSQL make before it runs.
            _check_chat_binds(n, args)
            return self._run_statement(method, n, args)
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
        if table == "chats":
            return list(self.chats.values())
        if table == "chat_messages":
            return list(self.chat_messages.values())
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
        if table in _CHAT_TABLES:
            # GH-176: encoders, then TEXT's U+0000 refusal and JSONB's input.
            return _chat_stored(table, values)
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
        elif table in _CHAT_TABLES:
            self.check_chat_row(table, row, original=original)
        else:
            msg = f"the fake's SQL reader never writes {table}"
            raise AssertionError(msg)

    # -- the chat tables of migration 0024 (GH-176) ----------------------------------

    def build_chat_row(
        self,
        table: str,
        given: dict[str, Any],
        now: datetime,
        *,
        pending: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """A new, checked chats / chat_messages row (an INSERT), not stored yet.

        The given values go through asyncpg's encoders and the server's input
        functions first; then the column defaults fill the rest (chat_messages
        takes the next ``seq``, consumed even when a later check fails, as an
        identity column's is); then every constraint runs. ``pending`` are the
        rows the same statement adds before this one (their keys count).
        """
        if "seq" in given:
            raise _pg_error(
                asyncpg.exceptions.GeneratedAlwaysError,
                'cannot insert a non-DEFAULT value into column "seq"',
                table=table,
                column="seq",
            )
        stored = self.normalized(table, given)
        row: dict[str, Any] = dict.fromkeys(_CHAT_TYPES[table])
        if table == "chats":
            row.update(
                id=uuid.uuid4(),
                title="",
                title_source="auto",
                external_content=False,
                created_at=now,
                last_activity_at=now,
            )
        else:
            self.chat_seq += 1
            row.update(id=uuid.uuid4(), seq=self.chat_seq, status="complete", created_at=now)
        row.update(stored)
        self.check_chat_row(table, row, original=None, pending=pending or [])
        return row

    def store_chat_row(self, table: str, row: dict[str, Any]) -> None:
        """Store a new row built by ``build_chat_row``."""
        target = self.chats if table == "chats" else self.chat_messages
        target[row["id"]] = row

    def check_chat_row(
        self,
        table: str,
        row: dict[str, Any],
        *,
        original: dict[str, Any] | None,
        pending: list[dict[str, Any]] | None = None,
    ) -> None:
        """Migration 0024's constraints on a written row, in PostgreSQL's order.

        NOT NULL (column order), the CHECKs (by constraint name), the unique keys
        (the primary key, chat_messages.seq, the partial unique
        ``chats_legacy_session_key`` over live chats only), then the foreign
        keys in creation order (chats -> organizations, then migration 0026's
        composite ``CHAT_OWNER_FKEY`` (owner_user_id, org_id) -> users (id,
        org_id): the owner must exist with the row's org; chat_messages ->
        organizations and the composite (chat_id, org_id) -> chats(id, org_id); a chat whose
        (id, org_id) changes while messages reference it is refused, NO ACTION).
        Each error carries the table, column or constraint name, and the
        CHECK / NOT NULL ones the "Failing row contains" detail (with content,
        as the driver's does).

        Before all of these, on an UPDATE of chats, migration 0025's BEFORE
        UPDATE row trigger (GH-266): turning external_content from true to false
        is CheckViolationError ``CHAT_EXTERNAL_CONTENT_RESET`` (SQLSTATE 23514, no
        row data, no table or constraint name, like a PL/pgSQL RAISE). A NULL
        passes the trigger and fails NOT NULL, as in PostgreSQL.
        """
        if (
            table == "chats"
            and original is not None
            and original["external_content"] is True
            and row.get("external_content") is False
        ):
            raise asyncpg.exceptions.CheckViolationError(CHAT_EXTERNAL_CONTENT_RESET)
        for column in _CHAT_TYPES[table]:
            if row.get(column) is None and column not in _CHAT_NULLABLE[table]:
                raise _pg_error(
                    asyncpg.exceptions.NotNullViolationError,
                    f'null value in column "{column}" of relation "{table}" violates'
                    " not-null constraint",
                    table=table,
                    column=column,
                    detail=_failing_row(table, row),
                )
        rules: list[tuple[str, bool]]
        if table == "chats":
            legacy = row["legacy_session_id"]
            rules = [
                (
                    "chats_legacy_session_id_check",
                    legacy is None or LEGACY_SESSION_ID_RE.fullmatch(legacy) is not None,
                ),
                ("chats_title_check", len(row["title"]) <= CHAT_TITLE_MAX),
                ("chats_title_source_check", row["title_source"] in CHAT_TITLE_SOURCES),
            ]
        else:
            blocks = row["tool_use_blocks"]
            calls = None if row["tool_calls"] is None else json.loads(row["tool_calls"])
            call_id = row["tool_call_id"]
            rules = [
                ("chat_messages_content_check", len(row["content"]) <= CHAT_CONTENT_MAX),
                ("chat_messages_role_check", row["role"] in CHAT_ROLES),
                ("chat_messages_status_check", row["status"] in CHAT_MESSAGE_STATUSES),
                (
                    "chat_messages_tool_call_id_check",
                    call_id is None or TOOL_CALL_ID_RE.fullmatch(call_id) is not None,
                ),
                (
                    "chat_messages_tool_calls_check",
                    calls is None
                    or (isinstance(calls, list) and len(calls) <= CHAT_TOOL_CALLS_MAX),
                ),
                (
                    "chat_messages_tool_use_blocks_check",
                    blocks is None or isinstance(json.loads(blocks), list),
                ),
            ]
        for constraint, valid in rules:
            if not valid:
                raise _pg_error(
                    asyncpg.exceptions.CheckViolationError,
                    f'new row for relation "{table}" violates check constraint "{constraint}"',
                    table=table,
                    constraint=constraint,
                    detail=_failing_row(table, row),
                )
        others = [other for other in self.table_rows(table) if other is not original]
        others += pending or []
        if any(other["id"] == row["id"] for other in others):
            raise _pg_error(
                asyncpg.exceptions.UniqueViolationError,
                f'duplicate key value violates unique constraint "{table}_pkey"',
                table=table,
                constraint=f"{table}_pkey",
                detail=f"Key (id)=({row['id']}) already exists.",
            )
        if table == "chat_messages" and any(other["seq"] == row["seq"] for other in others):
            raise _pg_error(
                asyncpg.exceptions.UniqueViolationError,
                'duplicate key value violates unique constraint "chat_messages_seq_key"',
                table=table,
                constraint="chat_messages_seq_key",
            )
        if (
            table == "chats"
            and row["legacy_session_id"] is not None
            and row["deleted_at"] is None
            and any(
                other["owner_user_id"] == row["owner_user_id"]
                and other["legacy_session_id"] == row["legacy_session_id"]
                and other["deleted_at"] is None
                for other in others
            )
        ):
            # The driver's DETAIL repeats the key, legacy session id included.
            raise _pg_error(
                asyncpg.exceptions.UniqueViolationError,
                'duplicate key value violates unique constraint "chats_legacy_session_key"',
                table=table,
                constraint="chats_legacy_session_key",
                detail=(
                    f"Key (owner_user_id, legacy_session_id)=({row['owner_user_id']},"
                    f" {row['legacy_session_id']}) already exists."
                ),
            )
        foreign = [(f"{table}_org_id_fkey", "organizations", row["org_id"] in self.orgs)]
        if table == "chats":
            # GH-271 (migration 0026): (owner_user_id, org_id) -> users (id, org_id).
            # A Super Admin (org_id NULL) or another org's member matches no key.
            owner = self.users.get(row["owner_user_id"])
            foreign.append(
                (CHAT_OWNER_FKEY, "users", owner is not None and owner["org_id"] == row["org_id"])
            )
        else:
            parent = self.chats.get(row["chat_id"])
            foreign.append(
                (
                    "chat_messages_chat_fkey",
                    "chats",
                    parent is not None and parent["org_id"] == row["org_id"],
                )
            )
        for constraint, parent_table, valid in foreign:
            if not valid:
                raise _pg_error(
                    asyncpg.exceptions.ForeignKeyViolationError,
                    f'insert or update on table "{table}" violates foreign key constraint'
                    f' "{constraint}"',
                    table=table,
                    constraint=constraint,
                    detail=f'Key is not present in table "{parent_table}".',
                )
        if (
            table == "chats"
            and original is not None
            and (original["id"], original["org_id"]) != (row["id"], row["org_id"])
            and any(
                (message["chat_id"], message["org_id"]) == (original["id"], original["org_id"])
                for message in self.chat_messages.values()
            )
        ):
            raise _pg_error(
                asyncpg.exceptions.ForeignKeyViolationError,
                'update or delete on table "chats" violates foreign key constraint'
                ' "chat_messages_chat_fkey" on table "chat_messages"',
                table="chat_messages",
                constraint="chat_messages_chat_fkey",
            )

    def drop_chats(self, doomed: set[uuid.UUID]) -> None:
        """Delete chats rows and, ON DELETE CASCADE, their messages."""
        self.chats = {key: row for key, row in self.chats.items() if key not in doomed}
        self.chat_messages = {
            key: row for key, row in self.chat_messages.items() if row["chat_id"] not in doomed
        }

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
        """Delete one users, invitations, organizations, login_throttle, settings or chat
        row; a user's rows (chats and their messages included) and an org's rows
        cascade (ON DELETE CASCADE). Call ``check_delete`` first."""
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
            # GH-176: chats.org_id and chat_messages.org_id cascade too.
            self.drop_chats(
                {key for key, chat in self.chats.items() if chat["org_id"] == row["id"]}
            )
            self.chat_messages = {
                key: value
                for key, value in self.chat_messages.items()
                if value["org_id"] != row["id"]
            }
            return
        if table == "chats":
            self.drop_chats({row["id"]})
            return
        if table == "chat_messages":
            del self.chat_messages[row["id"]]
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
        # GH-176 / GH-271: the chats owner key (owner_user_id, org_id) -> users
        # (id, org_id) cascades, and each chat's messages with it.
        self.drop_chats(
            {key for key, chat in self.chats.items() if chat["owner_user_id"] == user_id}
        )
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
    GH-244: square brackets (an ``ARRAY[a, b]`` constructor) nest like
    parentheses, so the commas between their elements stay inside.
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
        elif char in "([":
            out.append(char if depth == 0 else " ")
            depth += 1
        elif char in ")]":
            depth -= 1
            out.append(char if depth == 0 else " ")
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
    """Cut a statement into its top-level clauses, keyed by the keyword that opens each.

    The FROM of a predicate ``a IS [NOT] DISTINCT FROM b`` opens no clause (GH-24).
    """
    masked = re.sub(
        r"(?<![\w.])is (?:not )?distinct from(?!\w)",
        lambda match: " " * len(match.group(0)),
        _masked(text),
    )
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
    """One item of a FROM / JOIN / USING list: its alias, ON condition and join kind.

    A table (``table`` names it), or (GH-244) a sub-select ``[LATERAL] (SELECT ...)
    alias``: ``query`` is its SELECT, ``table`` the key of its output columns in
    ``_Statement.derived``, and ``lateral`` whether it reads the items before it.
    """

    table: str
    alias: str
    on: str | None
    left: bool
    query: str | None = None
    lateral: bool = False


def _sources(text: str) -> list[_Source]:
    """The items of a FROM (or USING) list, in order."""
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
        piece_masked = _masked(piece)
        derived = re.fullmatch(
            r"(lateral )?(\( *\))(?: (?:as )?(?!on\b)(\w+))?(?: on (.+))?", piece_masked
        )
        if derived is not None:
            # GH-244: a sub-select in FROM, e.g. "LEFT JOIN LATERAL (SELECT ...) m ON true".
            alias, on = derived.group(3), derived.group(4)
            assert alias is not None, f"the fake needs an alias for a sub-select in FROM: {piece}"
            query = piece[derived.start(2) + 1 : derived.end(2) - 1].strip()
            assert query.startswith("select "), f"the fake can't read this FROM item: {piece}"
            sources.append(
                _Source(
                    query,
                    alias,
                    None if on is None else piece[derived.start(4) :],
                    kind.startswith("left"),
                    query=query,
                    lateral=derived.group(1) is not None,
                )
            )
        else:
            match = re.fullmatch(r"(?:only )?(\w+)(?: (?:as )?(?!on\b)(\w+))?(?: on (.+))?", piece)
            assert match is not None, f"the fake can't read this FROM item: {piece}"
            table, alias, on = match.groups()
            assert table in _COLUMNS, f"the fake's SQL reader doesn't model table {table}: {text}"
            sources.append(_Source(table, alias or table, on, kind.startswith("left")))
        assert (sources[-1].on is None) == (kind in {"first", "comma"}), f"a join needs ON: {piece}"
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


# ---------------------------------------------------------------------------
# GH-176: the chats and chat_messages tables (migration 0024): driver-shaped
# errors, asyncpg's encoders, PostgreSQL's JSONB input and row comparison.
# ---------------------------------------------------------------------------


def _pg_error(
    cls: type[asyncpg.PostgresError],
    message: str,
    *,
    table: str | None = None,
    column: str | None = None,
    constraint: str | None = None,
    detail: str | None = None,
) -> asyncpg.PostgresError:
    """A driver error carrying the fields asyncpg fills from the server's report.

    ``detail`` shows up in ``str(error)`` (``"<message>\\nDETAIL:  <detail>"``),
    as it does for a real asyncpg error.
    """
    error = cls(message)
    fields = {
        "schema_name": "public" if table else None,
        "table_name": table,
        "column_name": column,
        "constraint_name": constraint,
        "detail": detail,
    }
    for name, value in fields.items():
        if value is not None:
            setattr(error, name, value)
    return error


def _pg_text(value: Any) -> str:
    """A value as PostgreSQL's text output roughly shows it (for error details)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "t" if value else "f"
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    return str(value)


def _failing_row(table: str, row: dict[str, Any]) -> str:
    """PostgreSQL's "Failing row contains (...)" detail: every column, each value
    cut to 64 bytes. Like the real driver's, it carries the row's content."""
    fields = []
    for column in _CHAT_TYPES[table]:
        text = _pg_text(row.get(column))
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > _FAILING_ROW_FIELD_MAX:
            text = encoded[:_FAILING_ROW_FIELD_MAX].decode("utf-8", "ignore") + "..."
        fields.append(text)
    return f"Failing row contains ({', '.join(fields)})."


def _encode_chat_value(kind: str, position: str, value: Any) -> Any:
    """asyncpg's encoder for one value of a chat column or bind parameter.

    Returns the value as the table stores it (a plain uuid.UUID for a uuid). A
    value the encoder refuses (a non-bool for a boolean, a non-int for a bigint,
    a non-str for a text or jsonb, a naive datetime, a str that isn't a UUID, a
    str that can't be UTF-8 encoded: a lone surrogate) is a DataError whose text
    repeats the value's repr (at most 40 characters), as asyncpg's does.
    """
    if value is None:
        return None
    valid = True
    reason = f"{kind} expected"
    stored = value
    if kind == "uuid":
        if isinstance(value, uuid.UUID):
            stored = _canonical(value)
        elif isinstance(value, str):
            try:
                stored = uuid.UUID(value)
            except ValueError:
                valid, reason = False, "invalid UUID"
        else:
            valid = False
    elif kind in {"text", "jsonb"}:
        valid = isinstance(value, str)
        if valid:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                valid, reason = False, "surrogates not allowed"
    elif kind == "bool":
        valid = type(value) is bool
    elif kind == "int":
        valid = type(value) is int
    else:
        assert kind == "timestamptz", kind
        valid = isinstance(value, datetime) and value.tzinfo is not None
        if isinstance(value, datetime) and value.tzinfo is None:
            reason = "an aware datetime expected"
    if not valid:
        shown = repr(value)
        if len(shown) > 40:
            shown = shown[:40] + "..."
        msg = f"invalid input for query argument {position}: {shown} ({reason})"
        raise asyncpg.exceptions.DataError(msg)
    return stored


def _refuse_nul(value: str) -> None:
    """PostgreSQL's TEXT input refuses U+0000 (verified on postgres:16 for GH-176)."""
    if "\x00" in value:
        msg = "null character not permitted"
        raise asyncpg.exceptions.CharacterNotInRepertoireError(msg)


def _reject_json_constant(name: str) -> Any:
    """PostgreSQL's JSON has no NaN / Infinity (Python's json module accepts them)."""
    msg = f"invalid JSON constant {name}"
    raise ValueError(msg)


def _jsonb_order(value: Any) -> Any:
    """A JSON value with every object's keys in JSONB's storage order: shorter keys
    first, equal lengths by their bytes (what jsonb_out prints back)."""
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: (len(key.encode("utf-8")), key.encode("utf-8")))
        return {key: _jsonb_order(value[key]) for key in keys}
    if isinstance(value, list):
        return [_jsonb_order(item) for item in value]
    return value


def _json_strings(value: Any) -> list[str]:
    """Every string of a parsed JSON value, object keys included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [key, *_json_strings(item)]]
    if isinstance(value, list):
        return [text for item in value for text in _json_strings(item)]
    return []


def _jsonb_text(text: str) -> str:
    """PostgreSQL's JSONB input for JSON text bound as a str; returns what a read gives back.

    A raw U+0000 is refused like any text (CharacterNotInRepertoireError); text
    that isn't JSON (NaN and Infinity included) and an escaped lone surrogate
    are InvalidTextRepresentationError; the escape ``\\u0000`` is
    UntranslatableCharacterError ("unsupported Unicode escape sequence"). The
    result is re-serialized with JSONB's key order (duplicate keys: the last
    wins), so it may differ from the text that was sent.
    """
    _refuse_nul(text)
    try:
        parsed = json.loads(text, parse_constant=_reject_json_constant)
    except ValueError:
        msg = "invalid input syntax for type json"
        raise asyncpg.exceptions.InvalidTextRepresentationError(msg) from None
    strings = _json_strings(parsed)
    if any("\x00" in string for string in strings):
        # json.loads strict mode refuses a raw NUL, so this came from the escape.
        msg = "unsupported Unicode escape sequence"
        raise asyncpg.exceptions.UntranslatableCharacterError(msg)
    if any(0xD800 <= ord(char) <= 0xDFFF for string in strings for char in string):
        msg = "invalid input syntax for type json"
        raise asyncpg.exceptions.InvalidTextRepresentationError(msg)
    return json.dumps(_jsonb_order(parsed), ensure_ascii=False)


def _chat_stored(table: str, values: dict[str, Any]) -> dict[str, Any]:
    """The written values of a chats / chat_messages row as the table stores them.

    First asyncpg's encoders for every value (DataError), then the server's
    input functions: TEXT refuses U+0000, JSONB parses (see ``_jsonb_text``).
    """
    types = _CHAT_TYPES[table]
    stored: dict[str, Any] = {}
    for column, value in values.items():
        if column not in types:
            msg = f'column "{column}" of relation "{table}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        stored[column] = _encode_chat_value(types[column], f"({column})", value)
    for column, value in stored.items():
        if value is None:
            continue
        if types[column] == "text":
            _refuse_nul(value)
        elif types[column] == "jsonb":
            stored[column] = _jsonb_text(value)
    return stored


def _row_compare(operator: str, lefts: list[Any], rights: list[Any]) -> bool:
    """PostgreSQL's row-wise comparison ``(a, b) < (c, d)``.

    Ordering operators compare pairs left to right and stop at the first pair
    that is unequal or has a NULL: a NULL there makes the result NULL (not
    true), otherwise that pair decides. ``=`` holds when every pair is equal;
    ``<>`` when some pair is unequal; NULLs otherwise make either NULL.
    """
    pairs = list(zip(lefts, rights, strict=True))
    if operator in {"=", "<>", "!="}:
        unequal = any(
            left is not None and right is not None and not _compare("=", left, right)
            for left, right in pairs
        )
        if unequal:
            return operator != "="
        if any(left is None or right is None for left, right in pairs):
            return False
        return operator == "="
    for left, right in pairs:
        if left is None or right is None:
            return False
        if _compare("=", left, right):
            continue
        return _compare(operator[0], left, right)
    return operator in {"<=", ">="}


def _chat_param_types(n: str) -> dict[int, str]:
    """The type PostgreSQL infers for each bind parameter of a chat-table statement.

    From an explicit ``$n::<type>`` cast, a comparison or SET with a column
    (``col = $n``, ``$n < col``), a row comparison ``(a, b) < ($n, $m)``, an
    INSERT's VALUES or SELECT list position, and ``LIMIT $n`` (bigint). A
    parameter none of these types is left out (only its U+0000 is checked).
    """
    masked = _masked_literals(n)
    columns: dict[str, str] = {}
    for table, types in _CHAT_TYPES.items():
        if re.search(rf"\b{table}\b", masked):
            columns.update(types)
    found: dict[int, str] = {}

    def note(number: str, column: str | None, cast: str | None = None) -> None:
        kind = _CAST_TYPES.get(cast) if cast else None
        if kind is None and column is not None:
            kind = columns.get(column)
        if kind is not None:
            found.setdefault(int(number), kind)

    for match in re.finditer(r"\$(\d+) ?:: ?(\w+)", masked):
        note(match.group(1), None, match.group(2))
    for match in re.finditer(rf"(?<![\w.$])(?:\w+\.)?(\w+) ?{_COMPARISON} ?\$(\d+)", masked):
        note(match.group(2), match.group(1))
    for match in re.finditer(rf"\$(\d+)(?: ?:: ?\w+)? ?{_COMPARISON} ?(?:\w+\.)?(\w+)", masked):
        note(match.group(1), match.group(2))
    for match in re.finditer(rf"\(([^()]*)\) ?{_COMPARISON} ?\(([^()]*)\)", masked):
        lefts = [item.strip() for item in match.group(1).split(",")]
        rights = [item.strip() for item in match.group(2).split(",")]
        for left, right in zip(lefts, rights, strict=False):
            for column_text, param_text in ((left, right), (right, left)):
                param = re.fullmatch(r"\$(\d+)(?: ?:: ?\w+)?", param_text)
                column = re.fullmatch(r"(?:\w+\.)?(\w+)", column_text)
                if param is not None and column is not None:
                    note(param.group(1), column.group(1))
    if limit := re.search(r"\blimit \$(\d+)", masked):
        found.setdefault(int(limit.group(1)), "int")
    if head := re.match(r"insert into (\w+) ?\(([^)]*)\)", masked):
        table_types = _CHAT_TYPES.get(head.group(1), {})
        targets = [column.strip().strip('"') for column in head.group(2).split(",")]
        clauses = _clauses(n, ("insert into", "values", "select", "on conflict", "returning"))
        exprs: list[str] = []
        if "values" in clauses and _unwrap(clauses["values"]) != clauses["values"]:
            exprs = _top_split(clauses["values"][1:-1], ",")
        elif "select" in clauses:
            exprs = _top_split(_top_split(clauses["select"], r" from ")[0], ",")
        for column, expr in zip(targets, exprs, strict=False):
            param = re.fullmatch(r"\$(\d+)(?: ?:: ?\w+)?", expr)
            if param is not None and column in table_types:
                found.setdefault(int(param.group(1)), table_types[column])
    return found


def _check_chat_binds(n: str, args: tuple[Any, ...]) -> None:
    """What asyncpg and PostgreSQL check before a chat-table statement runs.

    The argument count (InterfaceError, asyncpg's text) and no gap in the
    ``$n`` numbering (IndeterminateDatatypeError); each typed parameter through
    asyncpg's encoder (DataError); every str argument through the server's text
    input (U+0000: CharacterNotInRepertoireError), used or not; then the
    grants of migration 0024: admino_app may not DELETE chats and may not
    UPDATE or DELETE chat_messages (InsufficientPrivilegeError); and those of
    migration 0025 (GH-266): an UPDATE of chats may SET only the
    ``CHAT_UPDATE_COLUMNS`` (another existing column: InsufficientPrivilegeError;
    a column chats doesn't have is left to the reader's UndefinedColumnError,
    which PostgreSQL raises first). GH-271: every column of a row-constructor
    piece ``(a, b, ...) = ...`` (a row, ``ROW(...)`` or a sub-select) is
    checked too, as PostgreSQL does.
    """
    masked = _masked_literals(n)
    numbers = {int(number) for number in re.findall(r"\$(\d+)", masked)}
    expected = max(numbers, default=0)
    if expected != len(args):
        plural = "s" if expected != 1 else ""
        verb = "was" if len(args) == 1 else "were"
        msg = (
            f"the server expects {expected} argument{plural} for this query,"
            f" {len(args)} {verb} passed"
        )
        raise asyncpg.exceptions.InterfaceError(msg)
    for number in range(1, expected + 1):
        if number not in numbers:
            msg = f"could not determine data type of parameter ${number}"
            raise asyncpg.exceptions.IndeterminateDatatypeError(msg)
    for number, kind in sorted(_chat_param_types(n).items()):
        _encode_chat_value(kind, f"${number}", args[number - 1])
    for index, arg in enumerate(args):
        if isinstance(arg, str):
            _encode_chat_value("text", f"${index + 1}", arg)
            _refuse_nul(arg)
    denied = re.match(
        r"(?:delete from (?:only )?(?:public\.)?(chats|chat_messages)"
        r"|update (?:only )?(?:public\.)?(chat_messages))\b",
        n,
    )
    if denied is not None:
        msg = f"permission denied for table {denied.group(1) or denied.group(2)}"
        raise asyncpg.exceptions.InsufficientPrivilegeError(msg)
    if _CHATS_UPDATE_RE.match(n) is not None:
        clauses = _clauses(n, ("update", "set", "from", "where", "returning"))
        for piece in _top_split(clauses["set"], ","):
            # GH-271: a row-constructor piece ``(a, b, ...) = ...`` (a row, ROW(...) or a
            # sub-select) names every column of its list; PostgreSQL checks each one.
            row_target = re.match(r"\(([^()]*)\) ?=", piece)
            if row_target is not None:
                columns = [column.strip() for column in row_target.group(1).split(",")]
            else:
                target = re.match(r"(?:\w+\.)?(\w+) ?=", piece)
                columns = [target.group(1)] if target is not None else []
            for column in columns:
                if column in _CHAT_TYPES["chats"] and column not in CHAT_UPDATE_COLUMNS:
                    msg = "permission denied for table chats"
                    raise asyncpg.exceptions.InsufficientPrivilegeError(msg)


def _select_items(text: str) -> list[tuple[str, str, str]]:
    """A SELECT / RETURNING list as (kind, output name, expression) triples.

    The kind is "aggregate", "predicate" (a comparison or IS [NOT] NULL, a
    boolean value) or "value"; the name is the alias, else a column's name,
    else an aggregate's function name, else "?column?".
    """
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
    return items


def _driver_value(value: Any) -> Any:
    """A value as an asyncpg row carries it: asyncpg UUIDs, arrays (GH-244) as lists."""
    if isinstance(value, uuid.UUID):
        return _pg(value)
    if isinstance(value, list):
        return [_driver_value(item) for item in value]
    return value


def _assert_evaluable(text: str) -> None:
    """Fail the test for a WHERE / ON text with a construct the reader doesn't evaluate."""
    masked = _masked(text)
    for keyword in ("or", "between", "exists", "like", "ilike", "any", "all", "case"):
        assert not re.search(rf"(?<![\w.]){keyword}(?!\w)", masked), (
            f"the fake doesn't evaluate {keyword.upper()}: {text}"
        )


# A simple operand: a qualified column, a bind parameter, a literal or a constant.
_SIMPLE_OPERAND: Final = (
    r"(?:[a-z_]\w*\.[a-z_]\w*|\$\d+(?: ?:: ?\w+)?|'[^']*'|-?\d+|true|false|null)"
)


def _early_atoms(where: str, aliases: set[str]) -> list[str]:
    """The AND-ed WHERE predicates that read only the FROM items ``aliases`` (GH-244).

    Only simple ones: a comparison or IS [NOT] NULL between qualified columns of
    those items, bind parameters and constants. Every row they reject would be
    rejected by the WHERE anyway, so ``contexts`` may apply them before a LATERAL
    sub-select runs (as PostgreSQL's planner does) instead of after.
    """
    atoms = []
    for atom in _top_split(_unwrap(where), r" and "):
        text = _masked_literals(atom)
        simple = re.fullmatch(
            rf"{_SIMPLE_OPERAND} ?{_COMPARISON} ?{_SIMPLE_OPERAND}"
            rf"|{_SIMPLE_OPERAND} is (?:not )?null",
            text,
        )
        qualifiers = set(re.findall(r"(?<![\w.$'])([a-z_]\w*)\.[a-z_]\w*", text))
        if simple is not None and qualifiers and qualifiers <= aliases:
            atoms.append(atom)
    return atoms


_Context = dict[str, tuple[str, dict[str, Any] | None]]


class _Statement:
    """One statement the SQL reader runs: the database, its bind args and now()."""

    def __init__(self, db: FakeDb, args: tuple[Any, ...], now: datetime) -> None:
        self.db = db
        self.args = args
        self.now = now
        # GH-24: the row contexts of the queries enclosing the scalar subquery being
        # evaluated (innermost last), for its correlated column references.
        self.outer: list[_Context] = []
        # GH-244: the output columns of each sub-select in a FROM list, keyed by its
        # SELECT text (the ``table`` of its ``_Source``).
        self.derived: dict[str, frozenset[str]] = {}

    # -- values and predicates ---------------------------------------------------

    def _arg(self, number: str) -> Any:
        index = int(number) - 1
        assert 0 <= index < len(self.args), f"${number} has no bound value"
        return self.args[index]

    def value(self, expr: str, ctx: _Context) -> Any:
        """Evaluate a value expression in a row context."""
        parenthesized = expr.strip().startswith("(")
        expr = _unwrap(expr)
        if parenthesized and expr.startswith("select "):
            return self.scalar(expr, ctx)
        if re.fullmatch(r"array ?\( *\)", _masked(expr)):
            return self.array(expr[expr.index("(") + 1 : -1].strip(), ctx)
        if re.fullmatch(r"array ?\[ *\]", _masked(expr)):
            # GH-244: an ARRAY[a, b, ...] constructor (a list, as asyncpg decodes it).
            inner = expr[expr.index("[") + 1 : -1].strip()
            return [self.value(item, ctx) for item in _top_split(inner, ",")] if inner else []
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
        """A column's value in a row context, resolved like PostgreSQL.

        The query's own FROM list first, then (in a correlated subquery, GH-24)
        each enclosing query's, nearest first: a qualifier names the nearest
        level's table of that alias, an unqualified column is the nearest level's
        that has it (ambiguous only within one level).
        """
        for scope in (ctx, *reversed(self.outer)):
            if qualifier is not None:
                if qualifier not in scope:
                    continue
                owners = [qualifier] if name in self.columns_of(scope[qualifier][0]) else []
            else:
                owners = [
                    alias for alias, (table, _) in scope.items() if name in self.columns_of(table)
                ]
                if not owners:
                    continue
            if len(owners) > 1:
                msg = f'column reference "{name}" is ambiguous'
                raise asyncpg.exceptions.AmbiguousColumnError(msg)
            if not owners:
                # The alias's table has no such column (no outer level is tried).
                msg = f'column "{name}" does not exist'
                raise asyncpg.exceptions.UndefinedColumnError(msg)
            row = scope[owners[0]][1]
            return None if row is None else row[name]
        if qualifier is not None:
            msg = f'missing FROM-clause entry for table "{qualifier}"'
            raise asyncpg.exceptions.UndefinedTableError(msg)
        msg = f'column "{name}" does not exist'
        raise asyncpg.exceptions.UndefinedColumnError(msg)

    def columns_of(self, table: str) -> frozenset[str]:
        """The columns of a modelled table, or of a sub-select in FROM (GH-244)."""
        return self.derived[table] if table in self.derived else _COLUMNS[table]

    def subquery(self, query: str, ctx: _Context) -> list[dict[str, Any]]:
        """The rows of a sub-select run for the enclosing row context ``ctx``.

        A correlated reference reads ``ctx`` (then the levels enclosing it), as
        in ``column``.
        """
        self.outer.append(ctx)
        try:
            return self.select(query)
        finally:
            self.outer.pop()

    def array(self, query: str, ctx: _Context) -> list[Any]:
        """``ARRAY(SELECT <one column> FROM ...)`` (GH-244), as PostgreSQL runs it.

        Evaluated for the enclosing row context (a correlated reference reads
        it, as in ``scalar``): one element per row, in the rows' order; no row:
        ``[]`` (an empty array, not NULL). More than one column:
        PostgresSyntaxError. Elements that are arrays build a multidimensional
        array, so they must all be non-NULL arrays of one length
        (NullValueNotAllowedError, ArraySubscriptError otherwise).
        """
        assert query.startswith("select "), f"the fake can't evaluate ARRAY({query})"
        if len(_top_split(_clauses(query, ("select", "from"))["select"], ",")) != 1:
            msg = "subquery must return only one column"
            raise asyncpg.exceptions.PostgresSyntaxError(msg)
        values = [next(iter(row.values())) for row in self.subquery(query, ctx)]
        if any(isinstance(value, list) for value in values):
            if any(value is None for value in values):
                msg = "cannot accumulate null arrays"
                raise asyncpg.exceptions.NullValueNotAllowedError(msg)
            if any(not value for value in values):
                msg = "cannot accumulate empty arrays"
                raise asyncpg.exceptions.ArraySubscriptError(msg)
            if len({len(value) for value in values}) > 1:
                msg = "cannot accumulate arrays of different dimensionality"
                raise asyncpg.exceptions.ArraySubscriptError(msg)
        return values

    def scalar(self, query: str, ctx: _Context) -> Any:
        """A scalar subquery ``(SELECT <one column> FROM ...)`` (GH-24), as PostgreSQL runs it.

        Evaluated for the enclosing row context ``ctx``, so a correlated
        reference (``m.chat_id = c.id``) reads the enclosing row (see
        ``column``); the tables are as the statement found them (the reader
        stores an INSERT's rows only after every row is built). No row: NULL;
        more than one row: CardinalityViolationError; more than one column:
        PostgresSyntaxError.
        """
        if len(_top_split(_clauses(query, ("select", "from"))["select"], ",")) != 1:
            msg = "subquery must return only one column"
            raise asyncpg.exceptions.PostgresSyntaxError(msg)
        rows = self.subquery(query, ctx)
        if len(rows) > 1:
            msg = "more than one row returned by a subquery used as an expression"
            raise asyncpg.exceptions.CardinalityViolationError(msg)
        return next(iter(rows[0].values())) if rows else None

    def holds(self, text: str, ctx: _Context) -> bool:
        """True when every AND-ed predicate of a WHERE / ON text holds."""
        text = _unwrap(text)
        _assert_evaluable(text)
        return all(self.atom(atom, ctx) for atom in _top_split(text, r" and "))

    def atom(self, atom: str, ctx: _Context) -> bool:
        """Evaluate one predicate."""
        atom = _unwrap(atom)
        if " and " in _masked(atom):
            return self.holds(atom, ctx)
        masked = _masked(atom)
        if match := re.fullmatch(r"(.+?) is (not )?distinct from (.+)", masked):
            # GH-24: NULL-safe; two NULLs are not distinct, one NULL is distinct from
            # anything else.
            left = self.value(atom[: match.end(1)], ctx)
            right = self.value(atom[match.start(3) :], ctx)
            if left is None or right is None:
                distinct = (left is None) != (right is None)
            else:
                distinct = not _compare("=", left, right)
            return distinct != bool(match.group(2))
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
        if match := re.fullmatch(r"(\( *\)) ?(<>|!=|<=|>=|=|<|>) ?(\( *\))", masked):
            # GH-176: a row comparison, e.g. the keyset "(last_activity_at, id) < ($3, $4)".
            lefts = _top_split(atom[1 : match.end(1) - 1], ",")
            rights = _top_split(atom[match.start(3) + 1 : -1], ",")
            if len(lefts) != len(rights):
                msg = "unequal number of entries in row expressions"
                raise asyncpg.exceptions.PostgresSyntaxError(msg)
            return _row_compare(
                match.group(2),
                [self.value(item, ctx) for item in lefts],
                [self.value(item, ctx) for item in rights],
            )
        if match := re.fullmatch(r"(.+?) ?(<>|!=|<=|>=|=|<|>) ?(.+)", masked):
            left = self.value(atom[: match.end(1)], ctx)
            right = self.value(atom[match.start(3) :], ctx)
            return _compare(match.group(2), left, right)
        msg = f"the fake can't evaluate the predicate {atom!r}"
        raise AssertionError(msg)

    # -- row sets ----------------------------------------------------------------

    def contexts(self, sources: list[_Source], where: str | None = None) -> list[_Context]:
        """Every combination of source rows that satisfies the ON conditions.

        GH-244: a sub-select's rows are its result; a LATERAL one runs once per
        combination of the items before it (it reads them, as in PostgreSQL),
        any other once for the whole statement (it can't). A LEFT JOIN without
        a matching row keeps the combination once, the item's columns NULL.
        Before a LATERAL sub-select runs, the combinations the statement's
        ``where`` rejects on those items alone are dropped (``_early_atoms``;
        the caller still applies the whole WHERE), so it runs for the
        candidate rows only.
        """
        contexts: list[_Context] = [{}]
        for index, source in enumerate(sources):
            if source.lateral and where is not None:
                _assert_evaluable(_unwrap(where))
                early = _early_atoms(where, {item.alias for item in sources[:index]})
                contexts = [ctx for ctx in contexts if all(self.atom(a, ctx) for a in early)]
            fixed: list[dict[str, Any]] | None = None
            if source.query is not None:
                self.derived[source.table] = frozenset(
                    name
                    for _, name, _ in _select_items(
                        _clauses(source.query, ("select", "from"))["select"]
                    )
                )
                if not source.lateral:
                    fixed = self.select(source.query)
            joined: list[_Context] = []
            for ctx in contexts:
                if source.query is None:
                    rows = self.db.table_rows(source.table)
                elif fixed is not None:
                    rows = fixed
                else:
                    rows = self.subquery(source.query, ctx)
                matched = [
                    candidate
                    for row in rows
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
        items = _select_items(text)
        if any(kind == "aggregate" for kind, _, _ in items):
            # One row over every context (no GROUP BY in the fake).
            assert all(kind == "aggregate" for kind, _, _ in items), "no GROUP BY in the fake"
            return [{key: self.aggregate(expr, contexts) for _, key, expr in items}]
        rows = []
        for ctx in contexts:
            row: dict[str, Any] = {}
            for kind, key, expr in items:
                value = self.atom(expr, ctx) if kind == "predicate" else self.value(expr, ctx)
                row[key] = _driver_value(value)
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
        sources = _sources(clauses["from"])
        contexts = self.filtered(self.contexts(sources, clauses.get("where")), clauses.get("where"))
        if "order by" in clauses:
            contexts = self.ordered(contexts, clauses["order by"])
        elif _primary_table(n) in _CHAT_TABLES:
            # GH-176: PostgreSQL promises no order without ORDER BY; the chat tables
            # answer newest-first, so code that relies on insertion order shows up.
            contexts = contexts[::-1]
        rows = self.project(clauses["select"], contexts)
        if "limit" in clauses:
            rows = rows[: self.limit(clauses["limit"])]
        return rows

    def limit(self, text: str) -> int | None:
        """A LIMIT value: a bigint (DataError otherwise), never negative; NULL: no limit."""
        value = self.value(text, {})
        if value is None:
            return None
        if type(value) is not int:
            msg = f"invalid input for LIMIT: {type(value).__name__} (an integer expected)"
            raise asyncpg.exceptions.DataError(msg)
        if value < 0:
            msg = "LIMIT must not be negative"
            raise asyncpg.exceptions.InvalidRowCountInLimitClauseError(msg)
        return value

    def insert(self, n: str) -> tuple[list[dict[str, Any]], int]:
        target = re.match(r"insert into (?:only )?(\w+)", n)
        if target is not None and target.group(1) in _CHAT_TABLES:
            return self.insert_chat(n)
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

    def insert_chat(self, n: str) -> tuple[list[dict[str, Any]], int]:
        """An INSERT into chats or chat_messages (GH-176, see the module docstring).

        ``INSERT INTO t (cols) VALUES (exprs) [RETURNING ...]`` (one row) or
        ``INSERT INTO t (cols) SELECT exprs FROM ... [WHERE ...]`` (one row per
        selected row; a select item may be a column, a literal or ``$n``). All
        rows are built and checked before any is stored (one statement: all or
        nothing). No ON CONFLICT.
        """
        clauses = _clauses(n, ("insert into", "values", "select", "on conflict", "returning"))
        assert "on conflict" not in clauses, f"the fake does no ON CONFLICT on chat tables: {n}"
        head = re.fullmatch(r"(\w+) ?\((.*)\)", clauses["insert into"])
        assert head is not None, f"name the columns of an INSERT: {n}"
        table = head.group(1)
        columns = [column.strip().strip('"') for column in head.group(2).split(",")]
        if len(set(columns)) != len(columns):
            msg = "a column is specified more than once"
            raise asyncpg.exceptions.DuplicateColumnError(msg)
        unknown = set(columns) - _COLUMNS[table]
        if unknown:
            msg = f'column "{sorted(unknown)[0]}" of relation "{table}" does not exist'
            raise asyncpg.exceptions.UndefinedColumnError(msg)
        candidates: list[dict[str, Any]] = []
        if "values" in clauses:
            values = clauses["values"]
            assert "select" not in clauses and _unwrap(values) != values, f"one VALUES row: {n}"
            exprs = _top_split(values[1:-1], ",")
            if len(exprs) != len(columns):
                msg = "INSERT has more target columns than expressions, or the reverse"
                raise asyncpg.exceptions.PostgresSyntaxError(msg)
            candidates.append(
                {
                    column: self.value(expr, {})
                    for column, expr in zip(columns, exprs, strict=True)
                    if expr != "default"
                }
            )
        else:
            assert "select" in clauses, f"no rows to add: {n}"
            select = _clauses(
                "select " + clauses["select"],
                ("select", "from", "where", "group by", "having", "order by", "limit", "offset"),
            )
            unsupported = {"group by", "having", "offset"} & select.keys()
            assert not unsupported, f"the fake can't read this INSERT ... SELECT: {n}"
            items = _top_split(select["select"], ",")
            assert not select["select"].startswith("distinct"), "no DISTINCT in the fake"
            if len(items) != len(columns):
                msg = "INSERT has more target columns than expressions, or the reverse"
                raise asyncpg.exceptions.PostgresSyntaxError(msg)
            contexts: list[_Context] = [{}]
            if "from" in select:
                contexts = self.filtered(
                    self.contexts(_sources(select["from"])), select.get("where")
                )
            if "order by" in select:
                contexts = self.ordered(contexts, select["order by"])
            if "limit" in select:
                contexts = contexts[: self.limit(select["limit"])]
            candidates.extend(
                {column: self.value(item, ctx) for column, item in zip(columns, items, strict=True)}
                for ctx in contexts
            )
        rows: list[dict[str, Any]] = []
        for given in candidates:
            rows.append(self.db.build_chat_row(table, given, self.now, pending=rows))
        for row in rows:
            self.db.store_chat_row(table, row)
        returned = (
            [
                item
                for row in rows
                for item in self.project(clauses["returning"], [{table: (table, row)}])
            ]
            if "returning" in clauses
            else []
        )
        return returned, len(rows)

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
