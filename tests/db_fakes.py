"""Shared in-memory database for the service and HTTP tests (GH-151 to GH-245).

``FakeDb`` stands in for the users, organizations, invitations, sessions,
password_reset_tokens, email_outbox, audit_events, login_throttle,
platform_settings, org_settings, user_settings, permissions, oauth_tokens,
memory, chats, chat_messages and attachments tables behind a pool-shaped
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
  DELETE chats (GH-194: until a shipped migration, 0032, grants it) nor UPDATE
  or DELETE chat_messages (InsufficientPrivilegeError; the cascades still run).
  JSONB values travel as JSON text (``$n::jsonb``, no codec, like
  ``oauth_tokens.scopes``): parsed on write, stored and
  returned as a JSON str, re-serialized with JSONB's key order (shorter keys
  first), so it may differ from the text sent; a list or dict bound directly
  is a DataError.
- Migration 0025 (GH-266): an UPDATE of chats may SET only title,
  title_source, last_activity_at, external_content and deleted_at
  (``CHAT_UPDATE_COLUMNS``; GH-194: the shipped GRANTs decide, 0032 adds
  trash_group_id); naming id, org_id, owner_user_id, created_at or
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
- GH-189 (contract C4, C14; migration 0029): ``chat_messages`` gains
  ``included_attachment_ids`` (UUID[], NULL; ALTER TABLE ... ADD COLUMN, so it
  comes last in the column order and in the "Failing row contains" detail,
  printed like array_out: ``{a,b}``, NULL elements as NULL). Its CHECK
  ``CHAT_INCLUDED_ATTACHMENTS_CHECK`` runs in alphabetical order (after
  content, before role): NULL passes; an empty array, a NULL element, a
  multidimensional array and any non-assistant row holding ids are
  CheckViolationError. The value travels as ``$n::uuid[]`` through asyncpg's
  array encoder (a non-UUID element is a DataError; nested lists of one length
  are a multidimensional array, others "non-homogeneous array", a DataError)
  and is stored as a list of plain UUIDs. S8' (``INSERT INTO chat_messages
  (..., status, included_attachment_ids) VALUES (..., $8, $9::uuid[]) RETURNING
  id``) runs on the reader like S8. T2' (``load_turn``'s ``_TURN_SQL``) adds
  ``ARRAY(SELECT ARRAY[a.id::text, a.filename, a.kind, a.page_count::text]
  FROM attachments a JOIN chat_messages am ON am.id = a.message_id AND
  am.org_id = a.org_id WHERE a.chat_id = c.id AND ... ORDER BY am.seq,
  a.created_at, a.id) AS attachment_rows`` (Decision 3 as amended: the files
  in the order they were sent, by the carrying message's seq, then upload
  order). The sub-select's FROM list is read like any other: the inner JOIN
  keeps only the attachments whose ``message_id`` names a message of their
  org (an unsent file, ``message_id`` NULL, matches no message), its WHERE
  reads ``c`` from the enclosing row, and its ORDER BY may sort by the joined
  table's columns. The reader casts a column or a parenthesized expression
  with ``::text`` (a uuid's canonical text, an int's digits, NULL stays NULL,
  so a NULL page count is a None element inside its inner array), and the
  array decodes as a list of four-element lists (``[]`` when nothing matches).
  ``col = ANY(<array>)`` scans every element of a multidimensional array.
- Helpers: ``add_chat(owner_user_id, *, org_id=None, chat_id=None, title='',
  title_source='auto', legacy_session_id=None, external_content=False,
  created_at=None, last_activity_at=None, deleted_at=None)`` (org_id: the
  owner's, another org refused by ``CHAT_OWNER_FKEY``; last_activity_at:
  created_at, itself now) and
  ``add_chat_message(chat_id, role, content, *, tool_use_blocks=None,
  tool_call_id=None, tool_calls=None, status='complete', created_at=None,
  included_attachment_ids=None)`` (org_id: the chat's; the next seq; the JSONB
  values as Python lists; GH-189: the ids through the ``uuid[]`` encoder and
  the CHECK) seed rows checked like an INSERT and return their ids;
  ``chat_row(chat_id)``, ``chats_of(user_id)`` (any deletion state, by
  created_at then id) and ``messages_of(chat_id)`` (by seq, the JSONB columns
  as Python values, ``included_attachment_ids`` as None or a fresh list of
  plain UUIDs) read copies back. ``add_account(user_id=...)`` gives an account
  a fixed id.

Attachments (GH-187, migration 0027; GH-188, migration 0028):
- ``attachments`` (``attachments``, keyed by id, insertion order): ``id`` (UUID
  primary key, NO default: the app generates it, so an INSERT without it is a
  NotNullViolationError), ``org_id`` (UUID NOT NULL, references organizations
  ON DELETE CASCADE), ``chat_id`` and ``owner_user_id`` (UUID NOT NULL),
  ``message_id`` (UUID; NULL: not sent yet; references chat_messages (id) ON
  DELETE CASCADE), ``filename`` (TEXT NOT NULL; ``attachments_filename_check``:
  1 to ``ATTACHMENT_FILENAME_MAX`` characters and none of U+0000 to U+001F,
  U+007F to U+009F, ``/`` or ``\\``, which is ``!~ '[[:cntrl:]/\\\\]'`` on
  postgres:16-alpine's en_US.utf8, verified: U+2028 / U+2029 / U+200B pass),
  ``kind`` (TEXT NOT NULL, one of ``ATTACHMENT_KINDS``), ``size_bytes``
  (BIGINT NOT NULL, 1 to ``ATTACHMENT_SIZE_MAX``), ``status`` (TEXT NOT NULL,
  default 'uploaded', one of ``ATTACHMENT_STATUSES``), ``failure_reason``
  (TEXT; set exactly when status is 'failed', and then fully matching
  ``FAILURE_REASON_RE``: no trailing newline), ``page_count`` (INTEGER, NULL
  or >= 0), ``created_at`` and ``updated_at`` (NOT NULL, default now()),
  ``deleted_at`` (NULL: live; set: trashed) and (GH-188, migration 0028's
  ALTER TABLE ... ADD COLUMN statements, so they come last in the column order
  and in the "Failing row contains" detail) ``token_estimate`` (INTEGER, NULL
  until the file is ready; ``attachments_token_estimate_check``: NULL or >= 0)
  and ``derived_bytes`` (BIGINT, the bytes of the file's derived files, NULL
  until the file is ready; ``attachments_derived_bytes_check``: NULL or >= 0;
  contract §12.4).
- Checked like the chat tables, with asyncpg's exception classes and in
  PostgreSQL's order: the bind values through asyncpg's encoders (DataError: a
  non-int size_bytes, page_count, token_estimate or derived_bytes, one outside
  int64 / int32, a str that isn't a UUID, a naive datetime, ...), TEXT's U+0000
  (CharacterNotInRepertoireError), NOT NULL in column order, the CHECKs in
  alphabetical order of their names (derived_bytes, failure_reason, filename,
  kind, page_count, size_bytes, status, token_estimate; verified on postgres:16)
  with the "Failing row contains (...)" detail (the filename in it, as the
  driver's), the primary key (UniqueViolationError), then the
  foreign keys in creation order: ``attachments_org_id_fkey``,
  ``attachments_message_id_fkey`` (NULL passes) and ``ATTACHMENT_CHAT_FKEY``,
  the composite (chat_id, org_id, owner_user_id) -> chats (id, org_id,
  owner_user_id) of migration 0027's ``chats_id_org_owner_key``: another org's
  chat, another owner's chat and an unknown chat are ForeignKeyViolationError
  (the detail names the parent table, no key values); a trashed chat still
  matches.
- Cascades: deleting a users row (its chats), a chats row or an organizations
  row (the reader's DELETE and the ``purge_org_audit_events`` emulation)
  deletes the attachments of those chats and of that org; deleting a
  chat_messages row (only through its chat or org: admino_app can't DELETE
  chat_messages) deletes the attachments naming it. ``conn.transaction()``
  snapshots and restores the table.
- Grants (admino_app, migrations 0027 and 0028): SELECT, INSERT and DELETE; an
  UPDATE may SET only the shipped column grant (``ATTACHMENT_UPDATE_COLUMNS``,
  GH-190: read from the migrations' GRANTs; through 0029: message_id, status,
  failure_reason, page_count, token_estimate and derived_bytes (0028),
  updated_at, deleted_at; 0030 adds active, GH-194's 0032 trash_group_id).
  Naming id, org_id, chat_id, owner_user_id, filename, kind, size_bytes or
  created_at (also in a row-constructor piece) is InsufficientPrivilegeError
  "permission denied for table attachments", raised before the statement runs
  (nothing changes).
- Every statement naming attachments runs on the SQL reader after the
  chat-table bind checks (argument count, ``$n`` gaps, encoders, U+0000,
  grants). Reader features for the contract §2 forms (A1 to A11, P1 to P5, G1
  to G3):
  - ``col = ANY($n::uuid[])`` (and ``<>``) in a WHERE: the parameter goes
    through asyncpg's array encoder (a list, tuple or other sized iterable,
    not a str, bytes or mapping, each element a UUID, a UUID str or None;
    DataError otherwise). An empty array matches nothing; a NULL element or a
    NULL left side never matches.
  - ``FOR SHARE`` and ``FOR KEY SHARE`` (A2), like ``FOR UPDATE`` and ``FOR NO
    KEY UPDATE`` (A3): recorded, no effect (the fake has no row locks); any of
    them with an aggregate is FeatureNotSupportedError.
  - ``sum(col)``: NULL over no rows. As on postgres:16, the sum of a BIGINT
    column (size_bytes, derived_bytes, chat_messages.seq,
    organizations.storage_quota_bytes) is NUMERIC, so asyncpg returns a
    ``decimal.Decimal``; ``coalesce(sum(size_bytes), 0)`` (A4, A7) is
    ``Decimal(0)`` over no rows and the Decimal total otherwise (equal to the
    int, but not an int: callers convert). So is the sum of a BIGINT
    expression (GH-188's A4' / A7' ``sum(size_bytes + coalesce(derived_bytes,
    0))``: bigint + bigint is a bigint; a NULL derived_bytes counts 0). Any
    other sum is an int. ``count(*)`` is an int.
  - An unaliased ``coalesce(<aggregate>, ...)`` select item is named
    "coalesce", as in PostgreSQL.
  - A SELECT on attachments without ORDER BY answers newest-first, like the
    chat tables (PostgreSQL promises no order); ``ORDER BY created_at, id``
    (P5, G1) sorts by both. ``UPDATE ... RETURNING`` gives the new values (P1;
    GH-188's P1' ``RETURNING kind, filename``), ``DELETE ... RETURNING`` the
    deleted rows (G2); ``now()`` in SET is the statement's clock. An UPDATE's
    status is "UPDATE <n>" (GH-188's P2' sets ``page_count = $3,
    token_estimate = $4``, its P2'' also ``derived_bytes = $5``, and both
    answer "UPDATE 0" when no row matched).
  - GH-188 (contract §6, §7, §12.4): P1', P2' and P2'' above, A4' / A7'
    above, the ready transaction's A3 (like the upload's), and A5 / A6 with the
    R list ``id, chat_id, message_id, filename, kind, size_bytes, status,
    failure_reason, page_count, token_estimate, created_at``.
  - GH-189 (contract C5): A8' (``check_sendable``) selects ``id, message_id,
    status, filename, kind, page_count`` with A8's predicates and ``ORDER BY
    created_at, id``; T2' reads the chat's sent, live, ready attachments as a
    correlated ``ARRAY(SELECT ARRAY[...] FROM attachments a JOIN chat_messages
    am ... ORDER BY am.seq, a.created_at, a.id)`` (see Chats above).
  - A1 and A3 run on the reader like every SELECT whose main table is
    organizations (so ``after_org_lookup`` fires for them too). ``add_org``
    creates an org with ``storage_quota_bytes`` 0: under the contract's
    ``used + size > quota`` every upload is refused until a test sets a quota
    (``add_org(org_id, storage_quota_bytes=...)``).
- The audit action catalog (``audit_events_action_check``, migration 0027): an
  INSERT INTO audit_events whose action isn't in the shipped catalog
  (``AUDIT_ACTIONS``: migration 0021's catalog plus file.upload; GH-190: 0030's
  once it ships, see below) is CheckViolationError, before the foreign key;
  ``add_audit`` seeds any action.
- The audit metadata rule (``AUDIT_METADATA_CHECK``,
  ``audit_events_metadata_check``; GH-189 contract Amendment A1): every INSERT
  INTO audit_events is checked after the action catalog and before the
  foreign key (PostgreSQL runs a table's CHECKs in name order, its foreign
  keys at the end of the statement); a refusal is CheckViolationError naming
  the constraint, with nothing stored. The fake enforces the definition the
  shipped migrations leave in place (``audit_metadata_check_amended()``):
  0005's until a later migration re-adds the constraint, then the amended
  one. Both: a JSON object of at most 16 keys, each ``^[a-z][a-z0-9_]{0,39}$``,
  every value a scalar and every string value a ``^[a-z0-9_-]{1,64}$`` token.
  0005: no array anywhere, at most 4096 bytes. Amended: at most 8192 bytes,
  and ``attachment_ids`` (only it, when present) is an array of 1 to 100
  canonical lowercase UUID strings. The byte count is that of PostgreSQL's
  jsonb text form (``metadata::text``) as the fake's JSONB input
  (``_jsonb_text``) approximates it: jsonb key order, duplicate keys
  collapsed (the last wins), ``", "`` and ``": "`` separators, strings UTF-8
  (not ``\\u``-escaped), integers as written, floats as Python prints them.
  ``add_audit`` seeds without this check too.
- Helpers: ``add_attachment(chat_id, *, attachment_id=None, filename='a.pdf',
  kind='pdf', size_bytes=1, status='uploaded', failure_reason=None,
  page_count=None, token_estimate=None, derived_bytes=None, message_id=None,
  created_at=None, updated_at=None, deleted_at=None)`` stores a row checked
  like an INSERT
  (org_id and owner_user_id: the chat's, an unknown chat is
  ForeignKeyViolationError ``ATTACHMENT_CHAT_FKEY``; attachment_id: a new
  uuid4; created_at: now; updated_at: created_at) and returns its id (a plain
  uuid.UUID);
  ``attachment_row(attachment_id)`` reads a copy back (None when there is
  none) and ``attachments_of(chat_id)`` copies of a chat's rows, trashed ones
  included, by created_at then id.

Context budgeting and attachment exclusion (GH-190, migration 0030; contract C5,
C6, C7, C10):
- The schema follows the shipped migrations (``shipped_schema()``: the
  ``ShippedSchema`` that ``read_shipped_schema`` reads from the migrations next
  to the imported ``admino.database``, comments removed). Until a migration
  ships them, the fake is 0029's schema: there is no ``attachments.active`` (a
  statement on attachments that names ``active`` outside a literal is
  UndefinedColumnError when it is parsed, before its arguments are encoded and
  whatever rows exist; ``add_attachment`` stores no ``active`` key and refuses
  any other value than True), max_context_messages must be 1 to 200, and
  file.exclude / file.include are refused by ``audit_events_action_check``.
  Once the migrations directory holds a ``0030_*.sql`` with those statements,
  it is 0030's schema:
  - ``attachments.active`` BOOLEAN NOT NULL DEFAULT true, appended after
    derived_bytes (column order, the "Failing row contains" detail, ``t`` /
    ``f``); a non-bool is a DataError, NULL a NotNullViolationError; admino_app
    may UPDATE it once a shipped GRANT says so (``GRANT UPDATE (active) ON
    attachments TO admino_app``; a later REVOKE takes it back); an INSERT
    without it (A5, ``add_attachment()``) stores true.
  - ``platform_settings.max_context_messages``: the BETWEEN bounds of the last
    CHECK a shipped migration puts on it (0013's 1 to 200, 0030's 0 to 200),
    seeded and through the reader alike.
  - The audit action catalog: the IN list of the last
    ``audit_events_action_check`` a shipped migration adds (``AUDIT_ACTIONS`` is
    0027's; 0030's adds file.exclude and file.include).
  - Tests switch the schema with ``monkeypatch.setattr(db_fakes,
    "shipped_schema", lambda: db_fakes.read_shipped_schema(<a tmp copy of the
    migrations>))`` (tests/test_fakedb_context_budget.py builds 0029's and
    0030's that way); the schema is fixed before a test seeds its rows.
- The SQL forms run on the reader as PostgreSQL answers them, with one new
  reader feature: ``coalesce($n, col)`` / ``coalesce(col, $n)`` types ``$n`` as
  the column (A11's ``status = coalesce($4, status) AND active = coalesce($5,
  active)``: a non-str status or a non-bool flag is a DataError). T2''
  (``a.token_estimate::text``, ``a.derived_bytes::text`` and the bare boolean
  ``a.active`` in the correlated ARRAY sub-select: six-element text arrays, NULL
  as None), A8'' and A12 (``active`` / ``token_estimate`` / ``derived_bytes``
  selected, the bare ``active`` predicate), A5' / A6' / A10a / A11 / A11' (the
  R list with ``active`` before created_at; FOR UPDATE recorded; A11' the keyset
  row comparison ``(created_at, id) > ($6, $7)``), A10b (``SET active = $3``,
  "UPDATE <n>"), P6 (the attachments self-join, aliases ``a`` and ``o``;
  ``coalesce(sum(o.token_estimate), 0)`` is an int, 0 over no row: sum(integer)
  is bigint, which asyncpg returns as an int), P3'' (failed with reason and
  estimate, "UPDATE 0" unless processing), S9' / S11' (a correlated
  ``ARRAY(SELECT a.id ... ORDER BY a.created_at, a.id)`` per message row: a list
  of asyncpg UUIDs, ``[]`` without files). S9' / S11' and P3'' name no
  ``active``: they run before 0030 too.
- Helpers: ``add_attachment(..., active=True)`` (``active=False`` seeds an
  excluded file once 0030 ships); ``attachment_row(id)["active"]`` and
  ``attachments_of(chat_id)`` read the flag back (no key before 0030).

The trash: restore, delete forever and the retention purge (GH-194, migration
0032; contract §1, §2, §5):
- Gated on the shipped migrations like 0030 (``ShippedSchema.trash_group_tables``,
  ``trash_group_checks``, ``chat_update_columns``, ``delete_tables``; the
  defaults are 0030's schema). Until a shipped migration adds them there is no
  ``trash_group_id`` key in any row: a statement on chats or attachments that
  names the column is UndefinedColumnError when it is parsed (before its
  arguments are encoded, whatever rows exist), ``add_chat`` /
  ``add_attachment(trash_group_id=...)`` refuse it the same way, admino_app
  may not DELETE chats (InsufficientPrivilegeError) and chat.purge /
  file.purge are refused by ``audit_events_action_check``. The gate reads the
  statements, never a version number: GH-245's ``0031_chat_retry.sql`` adds
  none of them, so it leaves the trash schema off. Once a shipped migration
  (``0032_trash.sql``) runs the contract's statements:
  - ``chats.trash_group_id`` and ``attachments.trash_group_id`` (UUID, NULL;
    ALTER TABLE ... ADD COLUMN, so each is its table's last column, after
    attachments.active, and last in the "Failing row contains" detail): the
    id of the item whose deletion moved the row to the trash.
  - ``chats_trash_group_check`` / ``attachments_trash_group_check``
    (``TRASH_GROUP_CHECKS``): ``(deleted_at IS NULL) = (trash_group_id IS
    NULL)`` on every INSERT and UPDATE (seeds included), CheckViolationError
    with the ``constraint_name`` and the row's detail; the name sorts last, so
    it runs after every other CHECK of the table.
  - Grants (read from the GRANT / REVOKE statements, table-level and
    column-level, a table-level REVOKE taking the column grants with it):
    DELETE on chats, UPDATE (trash_group_id) on chats and attachments.
    ``DELETE FROM chats`` cascades to the chat's chat_messages and every
    attachments row of the chat (any state), never another chat's rows.
  - The catalog: 0030's plus chat.purge and file.purge.
- The SQL forms of contract §5 run on the reader as postgres:16 answered them
  (verified as admino_app for GH-194): R1, S6' and A10' (the chat its own group,
  its live files the chat's group; ``trash_group_id = id`` in SET reads the
  row's own id), A13, T1c / T1c' / T1a / T1a' (``deleted_at > $3``, the column
  comparison ``trash_group_id = id``, the keyset row comparison ``(deleted_at,
  id) < ($4, $5)``, ``ORDER BY deleted_at DESC, id DESC``, LIMIT), T2 (RETURNING
  the chat record; a restored legacy chat whose ``(owner_user_id,
  legacy_session_id)`` already has a live chat is UniqueViolationError on
  ``CHAT_LEGACY_SESSION_KEY``, nothing changed), T3, T4, T6, T7 and J3 (``FOR
  UPDATE``, recorded, no effect), T8, T9, T10, E1, E2, J1, J2, J4 and J5. Every
  timestamp parameter compared with deleted_at goes through the timestamptz
  encoder (an aware datetime, DataError otherwise); a comparison with a NULL
  deleted_at is not true. One new reader feature for J1: ``SELECT ... UNION
  [ALL] SELECT ... [ORDER BY <output column>, ...] [LIMIT $n]`` (left-associative;
  UNION removes duplicate rows, NULLs equal; the first SELECT names the
  columns; a different column count is PostgresSyntaxError; without ORDER BY
  the rows come back reversed).
- Helpers: ``add_chat(..., deleted_at=X)`` gives the chat ``trash_group_id`` =
  its id; ``add_attachment(..., deleted_at=X)`` its chat's id when that chat is
  trashed, else its own id (0032's backfill); a live row gets NULL; both take
  an explicit ``trash_group_id=`` (None included) checked like an INSERT.
  ``chat_row`` / ``attachment_row`` / ``attachments_of`` read the column back.

Retrying a failed answer (GH-245, migration 0031; contract C1, C2, C5):
- The SQL forms run on the reader as PostgreSQL answers them, with no new
  reader feature. R1 (``chats.read_retry_target``: the caller's live chat with
  two LEFT JOIN LATERAL sub-selects, ``latest`` (the latest message's seq and
  status) and ``turn`` (the latest user message's id, seq and content), and a
  correlated ``ARRAY(SELECT a.id ... ORDER BY a.created_at, a.id)`` of the
  turn row's live files, excluded ones included): one row per live chat of
  the caller (``fetchrow``), NULL ``through_seq`` / ``status`` / ``user_seq`` /
  ``content`` and ``[]`` for a chat without messages, a list of asyncpg UUIDs
  otherwise, no row for another org's, another owner's, a trashed or an
  unknown chat. T2b (``load_turn(..., before_seq=...)``: T2'' with ``AND seq <
  $5`` in the lateral's WHERE, the bound typed as the bigint seq) loads the
  latest ``limit`` messages before the bound; T2'' is unchanged.
- ``SELECT delete_failed_turn($1, $2, $3, $4)`` (optionally ``public.``,
  ``$n::uuid`` / ``$n::bigint`` casts and an ``AS`` alias; any other statement
  naming the function fails the test) emulates C1's plpgsql body, through
  ``fetchval`` (the deleted count, an int), ``fetchrow`` / ``fetch`` (a row
  ``{"delete_failed_turn": n}``) and ``execute`` ("SELECT 1"), on the pool or
  a connection; inside ``conn.transaction()`` it is undone with the
  transaction. In PostgreSQL's order: until a shipped migration creates the
  function (``shipped_functions()``, below) it is UndefinedFunctionError
  (also for another arity or a ``$n::text`` argument), raised before the
  arguments are checked; then the binds like a chat statement (argument count:
  InterfaceError; a ``$n`` gap: IndeterminateDatatypeError; a non-UUID chat,
  org or owner and a non-int or out-of-int64 through_seq: DataError); then
  admino_app's EXECUTE (``permission denied for function
  delete_failed_turn``, InsufficientPrivilegeError, when the migrations don't
  grant it); then C1's checks in C1's order, each refusal an
  InsufficientPrivilegeError ``DELETE_FAILED_TURN_REFUSAL`` ("only a failed
  turn of a live chat can be deleted", no row data) with nothing changed: the
  chat is live and of that org and owner; the row at through_seq (of that
  chat and org) is ``error`` or ``stopped`` (``FAILED_TURN_STATUSES``); no
  assistant or tool row of the chat follows it (user rows, e.g. an org notice,
  may); a user row at or before it exists (the turn starts at the latest
  one); every row strictly between that user row and through_seq is what a
  real failed turn holds there (C1', security audit M-1, with C1'b): a
  ``tool`` row or an ``assistant`` row with at least one tool_use block
  (``coalesce(jsonb_array_length(tool_use_blocks), 0) > 0``: NULL and ``[]``
  are none), with status ``complete`` or ``awaiting_confirmation``
  (``FAILED_TURN_BODY_STATUSES``), or an ``assistant`` row with status
  ``error`` (C1'b: GH-25 D9's partial reply of a streamed run that timed out
  after text, stored ``error`` as part of the failed answer; 0031 backfills
  the ones stored ``complete`` before). So a forged ``error`` row after a
  completed answer (stored ``complete``; admino_app can't UPDATE it), a
  completed tool turn or a ``limit_reached`` notice is refused (a forged row
  after a still-awaiting tool call is not: the documented residual). NULL
  arguments are refused the same way (the function isn't STRICT).
  Then every attachment of the turn user row in that chat and org (trashed and
  excluded ones too) gets ``message_id`` NULL and ``updated_at`` now, and the
  chat's rows from the turn's seq to through_seq are deleted (the ON DELETE
  CASCADE of ``attachments.message_id`` still runs, but reaches no unlinked
  file); the count is returned. A function the migrations don't make SECURITY
  DEFINER runs as admino_app and fails at its DELETE ("permission denied for
  table chat_messages", nothing changed).
- admino_app still may not DELETE or UPDATE chat_messages directly
  (InsufficientPrivilegeError "permission denied for table chat_messages", as
  before).
- ``shipped_functions()`` is the ``ShippedFunctions`` that
  ``read_shipped_functions`` reads from the migrations next to the imported
  ``admino.database`` (comments removed): ``created``, ``executable`` (by
  admino_app: PUBLIC's default EXECUTE until 0018's ``ALTER DEFAULT
  PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC``, then the GRANTs and
  REVOKEs of EXECUTE) and ``security_definer``. The fake reads the migrations
  of the tree it imports ``admino`` from, so a prototype tree run with
  ``PYTHONPATH=<tree>/src`` that holds ``0031_chat_retry.sql`` in
  ``<tree>/src/admino/migrations/`` runs the function with no patch. On a tree
  without 0031 a test switches with ``monkeypatch.setattr(db_fakes,
  "shipped_functions", lambda: db_fakes.read_shipped_functions(<a tmp copy of
  the migrations plus the contract's 0031>))`` (tests/test_fakedb_retry.py
  builds 0030's and 0031's that way), before it calls the function. 0031
  changes nothing ``shipped_schema()`` reads.

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
import functools
import hashlib
import json
import re
import secrets
import uuid
from collections.abc import Iterable, Mapping, Sized
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import asyncpg
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Sequence

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
        # GH-189 (migration 0029): ALTER TABLE ... ADD COLUMN appends it after
        # created_at; a UUID[] bound as ``$n::uuid[]`` through asyncpg's array encoder.
        "included_attachment_ids": "uuid[]",
    },
    # GH-187 (migration 0027): size_bytes is a BIGINT, page_count an INTEGER (their
    # encoders refuse values outside int64 / int32).
    "attachments": {
        "id": "uuid",
        "org_id": "uuid",
        "chat_id": "uuid",
        "owner_user_id": "uuid",
        "message_id": "uuid",
        "filename": "text",
        "kind": "text",
        "size_bytes": "int8",
        "status": "text",
        "failure_reason": "text",
        "page_count": "int4",
        "created_at": "timestamptz",
        "updated_at": "timestamptz",
        "deleted_at": "timestamptz",
        # GH-188 (migration 0028): ALTER TABLE ... ADD COLUMN appends them after
        # deleted_at; token_estimate an INTEGER like page_count, derived_bytes a
        # BIGINT like size_bytes (contract §12.4).
        "token_estimate": "int4",
        "derived_bytes": "int8",
        # GH-190 (migration 0030): ``active`` (BOOLEAN NOT NULL DEFAULT true) comes
        # after derived_bytes once a shipped migration adds it (``_chat_types``).
    },
}
_CHAT_NULLABLE: Final[dict[str, frozenset[str]]] = {
    # GH-194: trash_group_id (migration 0032) is nullable; it exists once 0032 ships.
    "chats": frozenset({"legacy_session_id", "deleted_at", "trash_group_id"}),
    "chat_messages": frozenset(
        {"tool_use_blocks", "tool_call_id", "tool_calls", "included_attachment_ids"}
    ),
    "attachments": frozenset(
        {
            "message_id",
            "failure_reason",
            "page_count",
            "deleted_at",
            "token_estimate",
            "derived_bytes",
            "trash_group_id",
        }
    ),
}
# The tables of the chat family: chats, chat_messages and (GH-187) attachments.
_CHAT_TABLES: Final = frozenset(_CHAT_TYPES)
# A statement that names a chat-family table (on the SQL with its literals blanked).
_CHAT_TABLE_RE: Final = re.compile(r"\b(?:chats|chat_messages|attachments)\b")
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
# GH-189 (migration 0029): the CHECK on chat_messages.included_attachment_ids.
CHAT_INCLUDED_ATTACHMENTS_CHECK: Final = "chat_messages_included_attachment_ids_check"
# GH-271 (migration 0026): the composite foreign key (owner_user_id, org_id) ->
# users (id, org_id) that ties a chat's owner to the chat's org (the only chats ->
# users key: it replaced 0024's chats_owner_user_id_fkey).
CHAT_OWNER_FKEY: Final = "chats_owner_org_fkey"
# GH-187 (migration 0027): the attachments CHECKs and the composite foreign key to
# the chat (and its owner and org). The columns admino_app may UPDATE are read from
# the shipped GRANTs (``ATTACHMENT_UPDATE_COLUMNS``, below ``shipped_schema``).
ATTACHMENT_KINDS: Final = frozenset(
    {"pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp"}
)
ATTACHMENT_STATUSES: Final = frozenset({"uploaded", "processing", "ready", "failed"})
ATTACHMENT_FILENAME_MAX: Final = 255
ATTACHMENT_SIZE_MAX: Final = 524_288_000
# failure_reason ~ '^[a-z][a-z0-9_]{0,63}$', read the way PostgreSQL reads it (fullmatch).
FAILURE_REASON_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
# filename !~ '[[:cntrl:]/\\]' on postgres:16-alpine (en_US.utf8): C0, DEL and C1
# controls, '/' and '\' (U+2028, U+2029, U+200B and U+00AD are not cntrl there).
_FILENAME_REFUSED_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f/\\]")
ATTACHMENT_CHAT_FKEY: Final = "attachments_chat_fkey"
# GH-190 (migration 0030): the column 0030 adds, the attachments table with it (column
# order: ALTER TABLE ... ADD COLUMN appends it after derived_bytes), and the name of
# the action catalog CHECK 0030 replaces.
ATTACHMENT_ACTIVE_COLUMN: Final = "active"
AUDIT_ACTION_CHECK: Final = "audit_events_action_check"
# GH-194 (migration 0032): the trash group column chats and attachments gain (ALTER
# TABLE ... ADD COLUMN appends it last), the CHECK that ties it to deleted_at on each
# table, and the partial unique index a restored chat's legacy session id can hit.
TRASH_GROUP_COLUMN: Final = "trash_group_id"
TRASH_GROUP_CHECKS: Final[dict[str, str]] = {
    "chats": "chats_trash_group_check",
    "attachments": "attachments_trash_group_check",
}
CHAT_LEGACY_SESSION_KEY: Final = "chats_legacy_session_key"
# The chat-family tables admino_app may DELETE from before 0032 (0027's attachments;
# 0024 grants no DELETE on chats or chat_messages).
_DELETE_TABLES_0030: Final = frozenset({"attachments"})
# The UPDATE statements a column grant applies to (normalized SQL): chats and
# attachments (the shipped GRANTs, ``_update_grant``).
_GRANTED_UPDATE_RE: Final = re.compile(r"update (?:only )?(?:public\.)?(chats|attachments)\b")
# The BIGINT columns the fake models: sum() of one is NUMERIC (a Decimal from asyncpg).
_BIGINT_COLUMNS: Final = frozenset({"size_bytes", "derived_bytes", "seq", "storage_quota_bytes"})
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
    "attachments": frozenset(_CHAT_TYPES["attachments"]),
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
# GH-187: audit_events_action_check as migration 0027 leaves it (0021's catalog plus
# file.upload). GH-190: the fake enforces the catalog of the shipped migrations
# (``shipped_schema().audit_actions``), which is this one until 0030 ships.
AUDIT_ACTIONS: Final = frozenset(
    {
        "login.success",
        "login.failure",
        "login.lockout",
        "password_reset.request",
        "password_reset.complete",
        "password.change",
        "session.revoke",
        "session.force_logout",
        "invitation.create",
        "invitation.revoke",
        "invitation.accept",
        "invitation.resend",
        "invitation.refuse",
        "user.role_change",
        "user.activate",
        "user.deactivate",
        "user.delete",
        "user.profile_change",
        "project.share",
        "project.unshare",
        "project.member_role_change",
        "project.transfer",
        "project.delete",
        "project.restore",
        "chat.delete",
        "chat.restore",
        "file.upload",
        "file.delete",
        "file.restore",
        "project.admin_access",
        "export.create",
        "org.settings_change",
        "org.create",
        "org.limits_change",
        "org.deactivate",
        "org.reactivate",
        "org.deletion_schedule",
        "org.deletion_cancel",
        "org.purge",
        "org.residency_change",
        "platform.settings_change",
        "model.registry_change",
        "breakglass.start",
        "breakglass.end",
        "tool.call",
        "audit.purge",
        "org.permission_change",
        "org.permission_promote",
        "org.permission_promote_cancel",
        "org.permission_demote",
    }
)
# The audit_events columns in the migration's order (a CHECK error's failing row).
_AUDIT_ROW_ORDER: Final = (
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
)
# GH-189 (contract Amendment A1): audit_events_metadata_check, as migration 0005
# defines it and as a later migration (0029) replaces it.
AUDIT_METADATA_CHECK: Final = "audit_events_metadata_check"
_AUDIT_METADATA_KEYS_MAX: Final = 16
_AUDIT_METADATA_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,39}")
_AUDIT_METADATA_TOKEN_RE: Final = re.compile(r"[a-z0-9_-]{1,64}")
_AUDIT_UUID_TEXT_RE: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_AUDIT_METADATA_BYTES_0005: Final = 4096
_AUDIT_METADATA_BYTES_AMENDED: Final = 8192
_AUDIT_ATTACHMENT_IDS_KEY: Final = "attachment_ids"
_AUDIT_ATTACHMENT_IDS_MAX: Final = 100
# A migration statement (comments removed, whitespace collapsed, lowercased) that
# re-adds the constraint.
_ADD_METADATA_CHECK_RE: Final = re.compile(
    rf'add constraint (?:"?public"?\.)?"?{AUDIT_METADATA_CHECK}"?\b'
)
_SQL_COMMENT_RE: Final = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)


# ---------------------------------------------------------------------------
# GH-190: the schema the shipped migrations leave in place, for what migration
# 0030 changes (attachments.active and its UPDATE grant, the max_context_messages
# CHECK, the audit action catalog). GH-194: and for what migration 0032 changes
# (trash_group_id on chats and attachments, their CHECKs, admino_app's DELETE on
# chats and UPDATE of the new columns, the catalog). Read from the migrations next
# to the imported ``admino.database``, comments removed, whitespace collapsed,
# lowercased.
# ---------------------------------------------------------------------------

_ADD_ACTIVE_RE: Final = re.compile(
    r'(?<![\w.])alter table (?:if exists )?(?:only )?(?:"?public"?\.)?"?attachments"?'
    r' add (?:column )?(?:if not exists )?"?active"?(?![\w"])'
)
# GH-194: ``ALTER TABLE chats|attachments ADD [COLUMN] trash_group_id ...`` (one statement).
_ADD_TRASH_GROUP_RE: Final = re.compile(
    r'alter table (?:if exists )?(?:only )?(?:"?public"?\.)?"?(chats|attachments)"?'
    rf' add (?:column )?(?:if not exists )?"?{TRASH_GROUP_COLUMN}"?(?![\w"]).*'
)
# GH-194: a trash group CHECK added (either side order) or a constraint dropped.
_ADD_TRASH_GROUP_CHECK_RE: Final = re.compile(
    r'alter table (?:only )?(?:"?public"?\.)?"?(?P<table>chats|attachments)"? add constraint'
    r' "?(?P<name>(?P=table)_trash_group_check)"? check ?\( ?'
    r"(?:\( ?deleted_at is null ?\) ?= ?\( ?trash_group_id is null ?\)"
    r"|\( ?trash_group_id is null ?\) ?= ?\( ?deleted_at is null ?\)) ?\)"
)
_DROP_CONSTRAINT_RE: Final = re.compile(
    r'alter table .*? drop constraint (?:if exists )?"?(?P<name>\w+)"?(?: cascade| restrict)?'
)
# GH-194: one GRANT or REVOKE statement on tables (privileges, table list, grantees).
_PRIVILEGE_STATEMENT_RE: Final = re.compile(
    r"(?P<verb>grant|revoke) (?:grant option for )?(?P<privileges>.+?) on (?:table )?"
    r'(?P<tables>(?:"?public"?\.)?"?\w+"?(?: ?, ?(?:"?public"?\.)?"?\w+"?)*)'
    r" (?:to|from) (?P<grantees>.+)"
)
# A comma between two privileges (not one inside a column list).
_PRIVILEGE_SPLIT_RE: Final = re.compile(r",(?![^()]*\))")
_PRIVILEGE_ITEM_RE: Final = re.compile(r"(\w+)(?: privileges)?(?: ?\(([^()]*)\))?")
_ALL_TABLE_PRIVILEGES: Final = frozenset(
    {"select", "insert", "update", "delete", "truncate", "references", "trigger"}
)
_CONTEXT_MESSAGES_BETWEEN_RE: Final = re.compile(
    r"check ?\( ?\(?max_context_messages between (\d+) and (\d+)\)? ?\)"
)
_ACTION_CATALOG_RE: Final = re.compile(
    rf'constraint "?{AUDIT_ACTION_CHECK}"? check ?\( ?\(?action\)? in ?\(([^()]*)\)'
)


@dataclass(frozen=True)
class ShippedSchema:
    """What a migrations directory leaves in place for the parts 0030 (GH-190) and
    0032 (GH-194) change.

    ``attachments_active``: a migration adds ``attachments.active`` (``ALTER
    TABLE attachments ADD COLUMN active ...``; the fake then models it as
    BOOLEAN NOT NULL DEFAULT true, contract C10). ``attachment_update_columns``:
    the columns admino_app may UPDATE on attachments (every column-level ``GRANT
    UPDATE (...) ON attachments TO admino_app``, minus the REVOKEs, in order).
    ``max_context_messages_bounds``: the BETWEEN bounds of the last CHECK on
    ``platform_settings.max_context_messages`` (0013's inline one, then any
    re-added one, e.g. 0030's ``platform_settings_max_context_messages_check``).
    ``audit_actions``: the IN list of the last ``AUDIT_ACTION_CHECK`` a
    migration adds (0005's inline one, then each replacement).

    GH-194 (the defaults are what 0001 to 0031 leave in place):
    ``trash_group_tables``: the tables a migration gives ``trash_group_id``
    (``ALTER TABLE chats|attachments ADD COLUMN trash_group_id ...``; the fake
    models it as a nullable UUID, the table's last column).
    ``trash_group_checks``: the ``TRASH_GROUP_CHECKS`` a migration adds (``CHECK
    ((deleted_at IS NULL) = (trash_group_id IS NULL))``) and no later one drops.
    ``chat_update_columns``: the columns admino_app may UPDATE on chats (0024's
    table-wide UPDATE, 0025's REVOKE and column grant, then every later GRANT /
    REVOKE). ``delete_tables``: the chat-family tables admino_app may DELETE from
    (table-level ``GRANT DELETE ON ...``, minus the REVOKEs).
    """

    attachments_active: bool
    attachment_update_columns: frozenset[str]
    max_context_messages_bounds: tuple[int, int]
    audit_actions: frozenset[str]
    trash_group_tables: frozenset[str] = frozenset()
    trash_group_checks: frozenset[str] = frozenset()
    chat_update_columns: frozenset[str] = CHAT_UPDATE_COLUMNS
    delete_tables: frozenset[str] = _DELETE_TABLES_0030


@dataclass
class _Privileges:
    """admino_app's privileges on the chat-family tables while the migrations are read.

    ``tables``: table-level privileges per table; ``columns``: column-level ones
    (privilege -> columns) per table. As in PostgreSQL, revoking a table-level
    privilege also revokes that privilege on every column.
    """

    tables: dict[str, set[str]]
    columns: dict[str, dict[str, set[str]]]

    def apply(self, statement: str) -> None:
        """Apply one GRANT / REVOKE statement (anything else is ignored)."""
        match = _PRIVILEGE_STATEMENT_RE.fullmatch(statement)
        if match is None or "admino_app" not in re.findall(r"\w+", match.group("grantees")):
            return
        grant = match.group("verb") == "grant"
        tables = [
            name.strip().replace('"', "").removeprefix("public.")
            for name in match.group("tables").split(",")
        ]
        for item in _PRIVILEGE_SPLIT_RE.split(match.group("privileges")):
            parsed = _PRIVILEGE_ITEM_RE.fullmatch(item.strip())
            assert parsed is not None, f"the fake can't read the privilege {item!r}"
            privilege, listed = parsed.groups()
            names = _ALL_TABLE_PRIVILEGES if privilege == "all" else frozenset({privilege})
            for table in tables:
                if table not in _CHAT_TABLES:
                    continue
                for name in names:
                    if listed is not None:
                        columns = {column.strip().strip('"') for column in listed.split(",")}
                        held = self.columns[table].setdefault(name, set())
                        if grant:
                            held |= columns
                        else:
                            held -= columns
                    elif grant:
                        self.tables[table].add(name)
                    else:
                        self.tables[table].discard(name)
                        self.columns[table].pop(name, None)

    def update_columns(self, table: str, columns: Iterable[str]) -> frozenset[str]:
        """The columns admino_app may UPDATE (``columns``: every column of the table)."""
        if "update" in self.tables[table]:
            return frozenset(columns)
        return frozenset(self.columns[table].get("update", set()))


def read_shipped_schema(directory: Path) -> ShippedSchema:
    """The ``ShippedSchema`` of the migrations in ``directory`` (``NNNN_*.sql``, in name order).

    Tests point it at a tmp copy of the migrations (with or without a 0030 or a
    0032 file) and monkeypatch ``shipped_schema`` to return the result.
    """
    active = False
    trash_tables: set[str] = set()
    trash_checks: set[str] = set()
    privileges = _Privileges(
        tables={table: set() for table in _CHAT_TABLES},
        columns={table: {} for table in _CHAT_TABLES},
    )
    bounds: tuple[int, int] | None = None
    actions: frozenset[str] | None = None
    for path in sorted(directory.glob("*.sql")):
        if re.match(r"\d{4}_", path.name) is None:
            continue
        sql = _SQL_COMMENT_RE.sub(" ", path.read_text(encoding="utf-8"))
        text = re.sub(r"\s+", " ", sql).lower()
        active = active or _ADD_ACTIVE_RE.search(text) is not None
        for statement in (piece.strip() for piece in text.split(";")):
            if added := _ADD_TRASH_GROUP_RE.fullmatch(statement):
                trash_tables.add(added.group(1))
            elif check := _ADD_TRASH_GROUP_CHECK_RE.fullmatch(statement):
                trash_checks.add(check.group("name"))
            elif dropped := _DROP_CONSTRAINT_RE.fullmatch(statement):
                trash_checks.discard(dropped.group("name"))
            privileges.apply(statement)
        for match in _CONTEXT_MESSAGES_BETWEEN_RE.finditer(text):
            bounds = (int(match.group(1)), int(match.group(2)))
        for match in _ACTION_CATALOG_RE.finditer(text):
            actions = frozenset(re.findall(r"'([^']*)'", match.group(1)))
    assert bounds is not None, f"no max_context_messages CHECK in {directory}"
    assert actions is not None, f"no {AUDIT_ACTION_CHECK} in {directory}"
    return ShippedSchema(
        attachments_active=active,
        attachment_update_columns=privileges.update_columns(
            "attachments", _chat_types_of("attachments", active, "attachments" in trash_tables)
        ),
        max_context_messages_bounds=bounds,
        audit_actions=actions,
        trash_group_tables=frozenset(trash_tables),
        trash_group_checks=frozenset(trash_checks),
        chat_update_columns=privileges.update_columns(
            "chats", _chat_types_of("chats", False, "chats" in trash_tables)
        ),
        delete_tables=frozenset(
            table for table in _CHAT_TABLES if "delete" in privileges.tables[table]
        ),
    )


@functools.cache
def _shipped_schema_of_the_tree() -> ShippedSchema:
    """``read_shipped_schema`` of the migrations next to the imported ``admino.database``."""
    from admino import database

    return read_shipped_schema(Path(database.__file__).parent / "migrations")


def shipped_schema() -> ShippedSchema:
    """The schema the fake models for what migrations 0030 (GH-190) and 0032 (GH-194) change.

    The shipped migrations decide: until one adds ``attachments.active`` the
    column doesn't exist (any statement naming it is UndefinedColumnError,
    ``add_attachment(active=False)`` too), until one re-adds the
    max_context_messages CHECK with ``BETWEEN 0 AND 200`` a 0 is refused, and
    until one adds file.exclude / file.include to the action catalog those
    actions are refused. GH-194: until one adds ``trash_group_id`` to chats and
    attachments the column doesn't exist (a statement naming it is
    UndefinedColumnError, ``add_chat`` / ``add_attachment(trash_group_id=...)``
    too), its CHECKs aren't there, admino_app may not DELETE chats nor UPDATE the
    column, and chat.purge / file.purge are refused. Every reader site calls
    this function at run time, so a test switches the schema with
    ``monkeypatch.setattr(db_fakes, "shipped_schema", lambda: schema)``.
    """
    return _shipped_schema_of_the_tree()


@functools.cache
def _chat_types_of(table: str, active: bool, trash_group: bool) -> dict[str, str]:
    """A chat-family table's column types in column order: the base columns, then the
    columns later migrations append (0030's ``active``, then 0032's ``trash_group_id``)."""
    types = dict(_CHAT_TYPES[table])
    if active:
        types[ATTACHMENT_ACTIVE_COLUMN] = "bool"
    if trash_group:
        types[TRASH_GROUP_COLUMN] = "uuid"
    return types


@functools.cache
def _chat_columns_of(table: str, active: bool, trash_group: bool) -> frozenset[str]:
    """The column names of ``_chat_types_of`` (cached: the reader asks for every column)."""
    return frozenset(_chat_types_of(table, active, trash_group))


def _chat_schema_key(table: str) -> tuple[str, bool, bool]:
    """The shipped schema's shape of a chat-family table (for ``_chat_types_of``)."""
    schema = shipped_schema()
    return (
        table,
        table == "attachments" and schema.attachments_active,
        table in schema.trash_group_tables,
    )


# The attachments columns admino_app may UPDATE after every shipped migration (the
# value when the fake was imported; the reader checks ``shipped_schema()`` itself).
ATTACHMENT_UPDATE_COLUMNS: Final = shipped_schema().attachment_update_columns


def _chat_types(table: str) -> dict[str, str]:
    """A chat-family table's column types in column order, as the shipped schema has them.

    GH-190: attachments gains ``active`` (bool, after derived_bytes) once a
    shipped migration adds it. GH-194: chats and attachments gain
    ``trash_group_id`` (uuid, last) once a shipped migration adds it.
    """
    return _chat_types_of(*_chat_schema_key(table))


def _table_columns(table: str) -> frozenset[str]:
    """The columns of a table the reader models, as the shipped schema has them (GH-190)."""
    if table in _CHAT_TABLES:
        return _chat_columns_of(*_chat_schema_key(table))
    return _COLUMNS[table]


def _update_grant(table: str) -> frozenset[str]:
    """The columns admino_app may SET in an UPDATE of chats or attachments (the shipped
    GRANTs; GH-194: chats' too, 0025's ``CHAT_UPDATE_COLUMNS`` until 0032 ships)."""
    if table == "chats":
        return shipped_schema().chat_update_columns
    return shipped_schema().attachment_update_columns


def _limit_bounds() -> dict[str, tuple[int, int]]:
    """The platform limits' CHECK bounds (0013's), max_context_messages as shipped (GH-190)."""
    return {**LIMIT_BOUNDS, "max_context_messages": shipped_schema().max_context_messages_bounds}


# ---------------------------------------------------------------------------
# GH-245: the database functions the shipped migrations leave in place, for
# migration 0031's ``delete_failed_turn`` (contract C1, C5). Read like
# ``shipped_schema``: comments removed, whitespace collapsed, lowercased.
# ---------------------------------------------------------------------------

DELETE_FAILED_TURN: Final = "delete_failed_turn"
# The text of every refusal of the function (SQLSTATE 42501, no row data).
DELETE_FAILED_TURN_REFUSAL: Final = "only a failed turn of a live chat can be deleted"
# The statuses the row at through_seq must have (the function's IN list).
FAILED_TURN_STATUSES: Final = frozenset({"error", "stopped"})
# C1' (security audit M-1): the statuses a tool row or a tool_use assistant row
# strictly between the turn's user row and through_seq must have (the shape
# check's IN list; C1'b admits any assistant row with status 'error' besides).
FAILED_TURN_BODY_STATUSES: Final = frozenset({"complete", "awaiting_confirmation"})
# The function's parameters in order, as asyncpg encodes them (uuid x 3, bigint).
_DELETE_FAILED_TURN_KINDS: Final = ("uuid", "uuid", "uuid", "int8")
_FUNCTION_NAME: Final = r'(?:"?public"?\.)?"?(\w+)"?'
_CREATE_FUNCTION_RE: Final = re.compile(
    rf"(?<![\w.])create (?:or replace )?function {_FUNCTION_NAME} ?\("
)
_DROP_FUNCTION_RE: Final = re.compile(rf"(?<![\w.])drop function (?:if exists )?{_FUNCTION_NAME}")
_ALTER_FUNCTION_RE: Final = re.compile(
    rf"(?<![\w.])alter function {_FUNCTION_NAME} ?\([^()]*\)(?P<rest>[^;]*)"
)
_FUNCTION_PRIVILEGE_RE: Final = re.compile(
    r"(?<![\w.])(?P<verb>grant|revoke) (?P<privileges>[^;]*?) on "
    r'(?P<target>all functions in schema "?public"?|function [^;]*?) (?:to|from) '
    r"(?P<grantees>[^;]*)"
)
_DEFAULT_FUNCTION_REVOKE_RE: Final = re.compile(
    r"(?<![\w.])alter default privileges [^;]*?revoke (?:execute|all(?: privileges)?)"
    r" on functions from public\b"
)
_DOLLAR_QUOTE_RE: Final = re.compile(r"\$(\w*)\$")
# The one form the app calls the function with (normalized SQL).
_DELETE_FAILED_TURN_RE: Final = re.compile(
    rf"select (?:public\.)?{DELETE_FAILED_TURN} ?\((?P<args>[^()]*)\)(?: as (?P<alias>\w+))?;?"
)


def _failed_turn_body_row(row: Mapping[str, Any]) -> bool:
    """Whether a stored chat_messages row may sit strictly between a failed turn's user
    row and through_seq (C1', security audit M-1, amended by C1'b): what the shape
    check's ``NOT (...)`` admits, ``(status IN ('complete', 'awaiting_confirmation') AND
    (role = 'tool' OR (role = 'assistant' AND
    coalesce(jsonb_array_length(tool_use_blocks), 0) > 0))) OR (role = 'assistant' AND
    status = 'error')``. The second branch is GH-25 D9's partial reply (a streamed run
    that timed out after text), stored ``error`` with the failed answer since C1'b.
    status and role are NOT NULL; ``tool_use_blocks`` is NULL or a JSON array (its CHECK),
    so a NULL or ``[]`` column counts no tool_use block."""
    if row["role"] == "assistant" and row["status"] == "error":
        return True
    if row["status"] not in FAILED_TURN_BODY_STATUSES:
        return False
    if row["role"] == "tool":
        return True
    if row["role"] != "assistant" or row["tool_use_blocks"] is None:
        return False
    blocks = json.loads(row["tool_use_blocks"])
    assert isinstance(blocks, list), "chat_messages_tool_use_blocks_check keeps an array"
    return len(blocks) > 0


@dataclass(frozen=True)
class ShippedFunctions:
    """The functions a migrations directory leaves in place (GH-245).

    ``created``: every function a migration creates (``CREATE [OR REPLACE]
    FUNCTION``) and none drops. ``executable``: those of them admino_app may
    EXECUTE: PUBLIC's EXECUTE on a new function until a migration runs
    ``ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`` (0018),
    then each ``GRANT`` / ``REVOKE`` of EXECUTE (or ALL) ``ON FUNCTION ...`` or
    ``ON ALL FUNCTIONS IN SCHEMA public`` to or from ``admino_app`` or PUBLIC, in
    file order. ``security_definer``: those that run as their owner (SECURITY
    DEFINER in the CREATE or a later ALTER FUNCTION; a CREATE OR REPLACE without
    it runs as the caller again, as in PostgreSQL). Overloads aren't told apart
    (the migrations have none).
    """

    created: frozenset[str]
    executable: frozenset[str]
    security_definer: frozenset[str]


def _function_attributes(text: str, start: int) -> str:
    """A CREATE FUNCTION's attributes: its text from ``start`` to the body's opening
    dollar quote, plus what follows the closing one up to the ``;``."""
    opening = _DOLLAR_QUOTE_RE.search(text, start)
    if opening is None:
        end = text.find(";", start)
        return text[start : end if end >= 0 else len(text)]
    closing = text.find(opening.group(0), opening.end())
    if closing < 0:
        return text[start : opening.start()]
    tail = closing + len(opening.group(0))
    end = text.find(";", tail)
    return text[start : opening.start()] + " " + text[tail : end if end >= 0 else len(text)]


def read_shipped_functions(directory: Path) -> ShippedFunctions:
    """The ``ShippedFunctions`` of the migrations in ``directory`` (``NNNN_*.sql``, in name order).

    Tests point it at a tmp copy of the migrations (with or without a 0031
    file) and monkeypatch ``shipped_functions`` to return the result.
    """
    created: set[str] = set()
    public: set[str] = set()
    app: set[str] = set()
    definer: set[str] = set()
    public_by_default = True
    for path in sorted(directory.glob("*.sql")):
        if re.match(r"\d{4}_", path.name) is None:
            continue
        sql = _SQL_COMMENT_RE.sub(" ", path.read_text(encoding="utf-8"))
        text = re.sub(r"\s+", " ", sql).lower()
        events: list[tuple[int, str, re.Match[str]]] = [
            (match.start(), kind, match)
            for kind, pattern in (
                ("create", _CREATE_FUNCTION_RE),
                ("drop", _DROP_FUNCTION_RE),
                ("alter", _ALTER_FUNCTION_RE),
                ("privilege", _FUNCTION_PRIVILEGE_RE),
                ("default", _DEFAULT_FUNCTION_REVOKE_RE),
            )
            for match in pattern.finditer(text)
        ]
        for _, kind, match in sorted(events, key=lambda event: event[0]):
            if kind == "default":
                public_by_default = False
            elif kind == "create":
                name = match.group(1)
                if name not in created:
                    created.add(name)
                    app.discard(name)
                    (public.add if public_by_default else public.discard)(name)
                attributes = _function_attributes(text, match.end())
                is_definer = re.search(r"\bsecurity definer\b", attributes) is not None
                (definer.add if is_definer else definer.discard)(name)
            elif kind == "drop":
                for found in (created, public, app, definer):
                    found.discard(match.group(1))
            elif kind == "alter":
                rest = match.group("rest")
                if re.search(r"\bsecurity definer\b", rest):
                    definer.add(match.group(1))
                elif re.search(r"\bsecurity invoker\b", rest):
                    definer.discard(match.group(1))
            elif re.search(r"\b(?:execute|all)\b", match.group("privileges")):
                target = match.group("target")
                if target.startswith("all functions"):
                    names = set(created)
                else:
                    listed = re.sub(r"\([^()]*\)", "()", target[len("function ") :])
                    names = set(re.findall(rf"{_FUNCTION_NAME} ?\(", listed))
                grantees = set(re.findall(r"\w+", match.group("grantees")))
                for grantee, found in (("public", public), ("admino_app", app)):
                    if grantee in grantees:
                        if match.group("verb") == "grant":
                            found.update(names & created)
                        else:
                            found.difference_update(names)
    return ShippedFunctions(
        created=frozenset(created),
        executable=frozenset(name for name in created if name in public or name in app),
        security_definer=frozenset(definer & created),
    )


@functools.cache
def _shipped_functions_of_the_tree() -> ShippedFunctions:
    """``read_shipped_functions`` of the migrations next to the imported ``admino.database``."""
    from admino import database

    return read_shipped_functions(Path(database.__file__).parent / "migrations")


def shipped_functions() -> ShippedFunctions:
    """The database functions the fake models as shipped (GH-245).

    The shipped migrations decide: until one creates ``delete_failed_turn``
    (0031) the call is UndefinedFunctionError, as on PostgreSQL. The emulation
    calls this function at run time, so a test switches with
    ``monkeypatch.setattr(db_fakes, "shipped_functions", lambda:
    db_fakes.read_shipped_functions(<a tmp copy of the migrations>))``.
    """
    return _shipped_functions_of_the_tree()


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


# GH-194: the default of ``add_chat`` / ``add_attachment``'s ``trash_group_id`` (derived
# from ``deleted_at`` as 0032's backfill does; an explicit None is a value).
_DERIVED: Final = object()


def _refuse_trash_group_seed(table: str, value: Any) -> None:
    """GH-194: before 0032 ships, seeding ``trash_group_id`` is UndefinedColumnError."""
    if value is not _DERIVED:
        msg = f'column "{TRASH_GROUP_COLUMN}" of relation "{table}" does not exist'
        raise _pg_error(asyncpg.exceptions.UndefinedColumnError, msg, table=table)


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
        # GH-187: the chats' attachments (migration 0027), keyed by id (insertion order).
        self.attachments: dict[uuid.UUID, dict[str, Any]] = {}
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
        trash_group_id: Any = _DERIVED,
    ) -> uuid.UUID:
        """Store a chats row (GH-176) as migrations 0024 to 0026 allow it; return its id.

        ``org_id`` defaults to the owner's org; an owner that doesn't exist, or
        (GH-271, migration 0026) isn't a member of ``org_id``'s org, is a
        ForeignKeyViolationError on ``CHAT_OWNER_FKEY``. ``chat_id`` defaults to
        a new uuid4, ``created_at`` to now and ``last_activity_at`` to
        ``created_at``. Every value is checked like an INSERT (DataError,
        CharacterNotInRepertoireError, NotNull, the CHECKs, the partial unique
        legacy session key, the foreign keys). Returns a plain uuid.UUID.

        GH-194: once a shipped migration adds ``trash_group_id`` (0032), a
        trashed chat (``deleted_at`` set) is its own trash group by default
        (``trash_group_id`` = its id, what 0032's backfill gives an existing
        trashed chat) and a live one has none; an explicit ``trash_group_id=``
        is stored as given (checked like an INSERT, the trash group CHECK
        included). Before that, any ``trash_group_id=`` is UndefinedColumnError,
        as an INSERT naming the column would be.
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
        if "chats" not in shipped_schema().trash_group_tables:
            _refuse_trash_group_seed("chats", trash_group_id)
        elif trash_group_id is not _DERIVED:
            given[TRASH_GROUP_COLUMN] = trash_group_id
        elif deleted_at is not None:
            # GH-194: 0032's backfill makes every trashed chat its own trash group.
            chat_id = chat_id if chat_id is not None else uuid.uuid4()
            given[TRASH_GROUP_COLUMN] = chat_id
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
        included_attachment_ids: Sequence[Any] | None = None,
    ) -> uuid.UUID:
        """Store a chat_messages row (GH-176) as migration 0024 allows it; return its id.

        ``org_id`` is the chat's (a chat that doesn't exist is a
        ForeignKeyViolationError), ``seq`` the next identity value,
        ``created_at`` defaults to now. ``tool_use_blocks`` / ``tool_calls`` are
        Python values, sent as their JSON text like the app's ``$n::jsonb``
        (so a str holding U+0000 fails like the escape ``\\u0000``). Checked like
        an INSERT. The chat's ``last_activity_at`` is not touched (a seed).
        GH-189: ``included_attachment_ids`` (migration 0029) goes through the
        ``uuid[]`` encoder and ``CHAT_INCLUDED_ATTACHMENTS_CHECK`` like the app's
        ``$9::uuid[]``.
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
            "included_attachment_ids": included_attachment_ids,
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
        """Copies of a chat's chat_messages rows by seq; the JSONB columns as Python values.

        GH-189: ``included_attachment_ids`` is None or a list of plain UUIDs.
        """
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
                # GH-189: None or a fresh list of plain UUIDs (never the stored list).
                "included_attachment_ids": (
                    None
                    if row["included_attachment_ids"] is None
                    else list(row["included_attachment_ids"])
                ),
            }
            for row in rows
        ]

    def add_attachment(
        self,
        chat_id: uuid.UUID,
        *,
        attachment_id: uuid.UUID | None = None,
        filename: str = "a.pdf",
        kind: str = "pdf",
        size_bytes: int = 1,
        status: str = "uploaded",
        failure_reason: str | None = None,
        page_count: int | None = None,
        token_estimate: int | None = None,
        derived_bytes: int | None = None,
        message_id: uuid.UUID | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        deleted_at: datetime | None = None,
        active: Any = True,
        trash_group_id: Any = _DERIVED,
    ) -> uuid.UUID:
        """Store an attachments row (GH-187) as the shipped migrations allow it; return its id.

        ``org_id`` and ``owner_user_id`` are the chat's (a chat that doesn't
        exist is a ForeignKeyViolationError on ``ATTACHMENT_CHAT_FKEY``).
        ``attachment_id`` defaults to a new uuid4, ``created_at`` to now and
        ``updated_at`` to ``created_at``. Every value is checked like an INSERT
        (DataError, CharacterNotInRepertoireError, NotNull, the CHECKs, the
        primary key, the foreign keys: ``message_id`` must name a stored
        chat_messages row). Returns a plain uuid.UUID.

        GH-190: ``active`` (default True, the column's default) is stored once a
        shipped migration adds the column (a non-bool: DataError, None:
        NotNullViolationError); before that the row has no ``active`` key and
        any other value than True is UndefinedColumnError, as an INSERT naming
        the column would be.

        GH-194: once a shipped migration adds ``trash_group_id`` (0032), a
        trashed file (``deleted_at`` set) defaults to the trash group 0032's
        backfill gives it: its chat's id when that chat is trashed (the chat's
        deletion moved it), else its own id (deleted on its own); a live file
        has none. An explicit ``trash_group_id=`` is stored as given (checked
        like an INSERT, the trash group CHECK included). Before that, any
        ``trash_group_id=`` is UndefinedColumnError.
        """
        chat = (
            self.chats.get(uuid.UUID(int=chat_id.int)) if isinstance(chat_id, uuid.UUID) else None
        )
        if chat is None:
            raise _pg_error(
                asyncpg.exceptions.ForeignKeyViolationError,
                'insert or update on table "attachments" violates foreign key constraint'
                f' "{ATTACHMENT_CHAT_FKEY}"',
                table="attachments",
                constraint=ATTACHMENT_CHAT_FKEY,
                detail='Key is not present in table "chats".',
            )
        now = datetime.now(UTC)
        created = created_at if created_at is not None else now
        given: dict[str, Any] = {
            "id": attachment_id if attachment_id is not None else uuid.uuid4(),
            "org_id": chat["org_id"],
            "chat_id": chat_id,
            "owner_user_id": chat["owner_user_id"],
            "message_id": message_id,
            "filename": filename,
            "kind": kind,
            "size_bytes": size_bytes,
            "status": status,
            "failure_reason": failure_reason,
            "page_count": page_count,
            "created_at": created,
            "updated_at": updated_at if updated_at is not None else created,
            "deleted_at": deleted_at,
            "token_estimate": token_estimate,
            "derived_bytes": derived_bytes,
        }
        if active is not True or shipped_schema().attachments_active:
            given[ATTACHMENT_ACTIVE_COLUMN] = active
        if "attachments" not in shipped_schema().trash_group_tables:
            _refuse_trash_group_seed("attachments", trash_group_id)
        elif trash_group_id is not _DERIVED:
            given[TRASH_GROUP_COLUMN] = trash_group_id
        elif deleted_at is not None:
            # GH-194: 0032's backfill: the chat's group when the chat is trashed, else
            # the file's own.
            trashed_chat = chat["deleted_at"] is not None
            given[TRASH_GROUP_COLUMN] = chat["id"] if trashed_chat else given["id"]
        row = self.build_chat_row("attachments", given, now)
        self.store_chat_row("attachments", row)
        return uuid.UUID(int=row["id"].int)

    def attachment_row(self, attachment_id: uuid.UUID) -> dict[str, Any] | None:
        """A copy of a stored attachments row (GH-187), None when there is none."""
        row = self.attachments.get(uuid.UUID(int=attachment_id.int))
        return dict(row) if row is not None else None

    def attachments_of(self, chat_id: uuid.UUID) -> list[dict[str, Any]]:
        """Copies of a chat's attachments rows, trashed ones included, by created_at then id."""
        wanted = uuid.UUID(int=chat_id.int)
        rows = [dict(row) for row in self.attachments.values() if row["chat_id"] == wanted]
        return sorted(rows, key=lambda row: (row["created_at"], row["id"]))

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
                "attachments": self.attachments,
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
        self.attachments = state["attachments"]

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
        if re.search(rf"\b{DELETE_FAILED_TURN}\b", _masked_literals(n)):
            # GH-245 (migration 0031): the owner-run delete of a chat's failed last turn.
            return self._delete_failed_turn(method, n, args)
        if _CHAT_TABLE_RE.search(_masked_literals(n)):
            # GH-176: every statement naming chats or chat_messages runs on the reader,
            # after the checks asyncpg and PostgreSQL make before it runs.
            _refuse_missing_active(n)
            _refuse_missing_trash_group(n)
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
        if table == "attachments":
            return list(self.attachments.values())
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
                (column, low <= row[column] <= high)
                for column, (low, high) in _limit_bounds().items()
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
        """A new, checked chats / chat_messages / attachments row (an INSERT), not stored yet.

        The given values go through asyncpg's encoders and the server's input
        functions first; then the column defaults fill the rest (chat_messages
        takes the next ``seq``, consumed even when a later check fails, as an
        identity column's is; attachments.id has no default, GH-187); then
        every constraint runs. ``pending`` are the rows the same statement adds
        before this one (their keys count).
        """
        if "seq" in given:
            raise _pg_error(
                asyncpg.exceptions.GeneratedAlwaysError,
                'cannot insert a non-DEFAULT value into column "seq"',
                table=table,
                column="seq",
            )
        stored = self.normalized(table, given)
        row: dict[str, Any] = dict.fromkeys(_chat_types(table))
        if table == "chats":
            row.update(
                id=uuid.uuid4(),
                title="",
                title_source="auto",
                external_content=False,
                created_at=now,
                last_activity_at=now,
            )
        elif table == "attachments":
            # GH-187 (migration 0027): no id default (the app names the file with it).
            row.update(status="uploaded", created_at=now, updated_at=now)
            if ATTACHMENT_ACTIVE_COLUMN in row:
                # GH-190 (migration 0030): BOOLEAN NOT NULL DEFAULT true.
                row[ATTACHMENT_ACTIVE_COLUMN] = True
        else:
            self.chat_seq += 1
            row.update(id=uuid.uuid4(), seq=self.chat_seq, status="complete", created_at=now)
        row.update(stored)
        self.check_chat_row(table, row, original=None, pending=pending or [])
        return row

    def store_chat_row(self, table: str, row: dict[str, Any]) -> None:
        """Store a new row built by ``build_chat_row``."""
        targets = {
            "chats": self.chats,
            "chat_messages": self.chat_messages,
            "attachments": self.attachments,
        }
        targets[table][row["id"]] = row

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

        attachments (GH-187, migration 0027): its six CHECKs plus (GH-188,
        migration 0028) ``attachments_derived_bytes_check`` and
        ``attachments_token_estimate_check`` (alphabetical, as PostgreSQL runs
        them), the primary key, then ``attachments_org_id_fkey``,
        ``attachments_message_id_fkey`` and ``ATTACHMENT_CHAT_FKEY`` (chat_id,
        org_id, owner_user_id) -> chats (id, org_id, owner_user_id).

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
        for column in _chat_types(table):
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
            rules += self._trash_group_rules(table, row)
        elif table == "attachments":
            reason = row["failure_reason"]
            filename = row["filename"]
            page_count = row["page_count"]
            token_estimate = row["token_estimate"]
            derived_bytes = row["derived_bytes"]
            rules = [
                # GH-188 (migration 0028, contract §12.4).
                (
                    "attachments_derived_bytes_check",
                    derived_bytes is None or derived_bytes >= 0,
                ),
                (
                    "attachments_failure_reason_check",
                    (row["status"] == "failed") == (reason is not None)
                    and (reason is None or FAILURE_REASON_RE.fullmatch(reason) is not None),
                ),
                (
                    "attachments_filename_check",
                    1 <= len(filename) <= ATTACHMENT_FILENAME_MAX
                    and _FILENAME_REFUSED_RE.search(filename) is None,
                ),
                ("attachments_kind_check", row["kind"] in ATTACHMENT_KINDS),
                ("attachments_page_count_check", page_count is None or page_count >= 0),
                ("attachments_size_bytes_check", 1 <= row["size_bytes"] <= ATTACHMENT_SIZE_MAX),
                ("attachments_status_check", row["status"] in ATTACHMENT_STATUSES),
                # GH-188 (migration 0028).
                (
                    "attachments_token_estimate_check",
                    token_estimate is None or token_estimate >= 0,
                ),
            ]
            rules += self._trash_group_rules(table, row)
        else:
            blocks = row["tool_use_blocks"]
            calls = None if row["tool_calls"] is None else json.loads(row["tool_calls"])
            call_id = row["tool_call_id"]
            rules = [
                ("chat_messages_content_check", len(row["content"]) <= CHAT_CONTENT_MAX),
                # GH-189 (migration 0029).
                (
                    CHAT_INCLUDED_ATTACHMENTS_CHECK,
                    _included_attachment_ids_valid(row["role"], row["included_attachment_ids"]),
                ),
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
                f'duplicate key value violates unique constraint "{CHAT_LEGACY_SESSION_KEY}"',
                table=table,
                constraint=CHAT_LEGACY_SESSION_KEY,
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
        elif table == "attachments":
            # GH-187 (migration 0027): the column constraints first (creation order),
            # then the composite key to the chat, its org and its owner (MATCH SIMPLE;
            # every column is NOT NULL). A trashed chat is still a chats row.
            message_id = row["message_id"]
            chat = self.chats.get(row["chat_id"])
            foreign.append(
                (
                    "attachments_message_id_fkey",
                    "chat_messages",
                    message_id is None or message_id in self.chat_messages,
                )
            )
            foreign.append(
                (
                    ATTACHMENT_CHAT_FKEY,
                    "chats",
                    chat is not None
                    and (chat["org_id"], chat["owner_user_id"])
                    == (row["org_id"], row["owner_user_id"]),
                )
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

    @staticmethod
    def _trash_group_rules(table: str, row: dict[str, Any]) -> list[tuple[str, bool]]:
        """GH-194 (migration 0032): ``<table>_trash_group_check``, ``(deleted_at IS NULL) =
        (trash_group_id IS NULL)``, once a shipped migration adds it. Its name sorts
        after every other CHECK of chats and attachments, so it runs last."""
        constraint = TRASH_GROUP_CHECKS[table]
        if constraint not in shipped_schema().trash_group_checks:
            return []
        valid = (row["deleted_at"] is None) == (row.get(TRASH_GROUP_COLUMN) is None)
        return [(constraint, valid)]

    def drop_chats(self, doomed: set[uuid.UUID]) -> None:
        """Delete chats rows and, ON DELETE CASCADE, their messages and attachments."""
        self.chats = {key: row for key, row in self.chats.items() if key not in doomed}
        self.drop_messages(
            {key for key, row in self.chat_messages.items() if row["chat_id"] in doomed}
        )
        # GH-187: attachments_chat_fkey (chat_id, org_id, owner_user_id) cascades.
        self.attachments = {
            key: row for key, row in self.attachments.items() if row["chat_id"] not in doomed
        }

    def drop_messages(self, doomed: set[uuid.UUID]) -> None:
        """Delete chat_messages rows and (GH-187) the attachments naming them (CASCADE)."""
        self.chat_messages = {
            key: row for key, row in self.chat_messages.items() if key not in doomed
        }
        self.attachments = {
            key: row for key, row in self.attachments.items() if row["message_id"] not in doomed
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
        """Delete one users, invitations, organizations, login_throttle, settings or
        chat-family row; a user's rows (chats with their messages and attachments
        included), an org's rows and a chat's or message's rows cascade (ON DELETE
        CASCADE). Call ``check_delete`` first."""
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
            self.drop_messages(
                {key for key, value in self.chat_messages.items() if value["org_id"] == row["id"]}
            )
            # GH-187: attachments.org_id cascades too.
            self.attachments = {
                key: value
                for key, value in self.attachments.items()
                if value["org_id"] != row["id"]
            }
            return
        if table == "chats":
            self.drop_chats({row["id"]})
            return
        if table == "chat_messages":
            self.drop_messages({row["id"]})
            return
        if table == "attachments":
            del self.attachments[row["id"]]
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
        metadata_text = row["metadata"]
        row["target_ids"] = json.loads(row["target_ids"])
        row["metadata"] = json.loads(row["metadata"])
        row["ip"] = None if row["ip"] is None else str(row["ip"])
        if self.fail_audit_when is not None and self.fail_audit_when(row):
            raise AuditWriteError("the audit write was refused")
        if row.get("action") not in shipped_schema().audit_actions:
            # GH-187: audit_events_action_check (migration 0027; GH-190: the shipped
            # catalog, 0030's once it ships), before the foreign key.
            raise _audit_check_violation("audit_events_action_check", row)
        if not _audit_metadata_valid(metadata_text, amended=audit_metadata_check_amended()):
            # GH-189: audit_events_metadata_check (0005, or as a later migration
            # re-adds it), after the action CHECK (name order), before the foreign key.
            raise _audit_check_violation(AUDIT_METADATA_CHECK, row)
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

    def _delete_failed_turn(self, method: str, n: str, args: tuple[Any, ...]) -> Any:
        """``SELECT delete_failed_turn($1, $2, $3, $4)`` (GH-245, migration 0031, contract C1).

        In PostgreSQL's order: the call is resolved when the statement is
        prepared (UndefinedFunctionError until a shipped migration creates the
        function, or for another arity or argument type), then asyncpg's
        argument checks (count, ``$n`` gaps, the uuid and bigint encoders:
        InterfaceError / IndeterminateDatatypeError / DataError), then the
        EXECUTE privilege, then the body exactly as C1 states it, each refusal
        an InsufficientPrivilegeError ``DELETE_FAILED_TURN_REFUSAL`` with
        nothing changed: the live chat of that org and owner; the row at
        through_seq ended ``error`` or ``stopped``; no assistant or tool row
        after it; the latest user row at or before it (the turn); then (C1',
        security audit M-1) the turn's shape: every row strictly between that
        user row and through_seq is a ``tool`` row or an ``assistant`` row with
        at least one tool_use block, ``complete`` or ``awaiting_confirmation``
        (what a real failed turn holds there: tool calls, their results, an
        approval's awaiting row), or (C1'b) an ``assistant`` row with status
        ``error`` (GH-25 D9's partial reply before the error reply), so a row
        admino_app forged after a completed answer, tool turn or
        ``limit_reached`` notice deletes nothing. Then the
        turn user row's attachments are unlinked (``message_id`` NULL,
        ``updated_at`` now; trashed and excluded ones too) and the rows from
        the turn's seq to through_seq are deleted (their cascade reaches no
        unlinked file). Returns how many rows it deleted (an int; a row
        ``{"delete_failed_turn": n}`` for fetchrow / fetch, "SELECT 1" for
        execute). A function that doesn't run as its owner (no SECURITY
        DEFINER) fails at the DELETE: admino_app may not delete chat_messages.
        """
        form = (
            f"the fake runs {DELETE_FAILED_TURN} only as SELECT {DELETE_FAILED_TURN}($a, ...): {n}"
        )
        match = _DELETE_FAILED_TURN_RE.fullmatch(n)
        assert match is not None, form
        pieces = _top_split(match.group("args"), ",")
        params = [re.fullmatch(r"\$(\d+)(?: ?:: ?(\w+))?", piece) for piece in pieces]
        found = [param for param in params if param is not None]
        assert len(found) == len(params) or pieces == [""], form
        found = found if pieces != [""] else []
        casts = [param.group(2) for param in found]
        wanted = [kind if kind == "uuid" else "int" for kind in _DELETE_FAILED_TURN_KINDS]
        functions = shipped_functions()
        if (
            DELETE_FAILED_TURN not in functions.created
            or len(found) != len(_DELETE_FAILED_TURN_KINDS)
            or any(
                cast is not None and _CAST_TYPES.get(cast) != kind
                for cast, kind in zip(casts, wanted, strict=True)
            )
        ):
            shown = ", ".join(cast or "unknown" for cast in casts)
            msg = f"function {DELETE_FAILED_TURN}({shown}) does not exist"
            raise asyncpg.exceptions.UndefinedFunctionError(msg)
        _check_chat_binds(n, args)
        values = [
            _encode_chat_value(kind, f"${param.group(1)}", args[int(param.group(1)) - 1])
            for kind, param in zip(_DELETE_FAILED_TURN_KINDS, found, strict=True)
        ]
        if DELETE_FAILED_TURN not in functions.executable:
            msg = f"permission denied for function {DELETE_FAILED_TURN}"
            raise asyncpg.exceptions.InsufficientPrivilegeError(msg)
        chat_id, org_id, owner_id, through_seq = values
        refusal = asyncpg.exceptions.InsufficientPrivilegeError(DELETE_FAILED_TURN_REFUSAL)
        chat = self.chats.get(chat_id) if chat_id is not None else None
        if (
            chat is None
            or org_id is None
            or owner_id is None
            or chat["org_id"] != org_id
            or chat["owner_user_id"] != owner_id
            or chat["deleted_at"] is not None
        ):
            raise refusal
        rows = [
            row
            for row in self.chat_messages.values()
            if row["chat_id"] == chat_id and row["org_id"] == org_id
        ]
        if through_seq is None or not any(
            row["seq"] == through_seq and row["status"] in FAILED_TURN_STATUSES for row in rows
        ):
            raise refusal
        if any(row["seq"] > through_seq and row["role"] != "user" for row in rows):
            raise refusal
        users = [row for row in rows if row["role"] == "user" and row["seq"] <= through_seq]
        if not users:
            raise refusal
        turn = max(users, key=lambda row: row["seq"])
        if any(
            turn["seq"] < row["seq"] < through_seq and not _failed_turn_body_row(row)
            for row in rows
        ):
            raise refusal
        if DELETE_FAILED_TURN not in functions.security_definer:
            # Run as admino_app, the body's DELETE is refused and the statement undone.
            msg = "permission denied for table chat_messages"
            raise asyncpg.exceptions.InsufficientPrivilegeError(msg)
        now = datetime.now(UTC)
        for key, attachment in list(self.attachments.items()):
            if (
                attachment["message_id"] == turn["id"]
                and attachment["chat_id"] == chat_id
                and attachment["org_id"] == org_id
            ):
                self.attachments[key] = {**attachment, "message_id": None, "updated_at": now}
        doomed = {row["id"] for row in rows if turn["seq"] <= row["seq"] <= through_seq}
        self.drop_messages(doomed)
        deleted = len(doomed)
        key = match.group("alias") or DELETE_FAILED_TURN
        if method == "fetchval":
            return deleted
        if method == "fetchrow":
            return {key: deleted}
        if method == "fetch":
            return [{key: deleted}]
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


def _audit_check_violation(constraint: str, row: dict[str, Any]) -> asyncpg.PostgresError:
    """The CheckViolationError PostgreSQL raises for an audit_events CHECK, with the row."""
    failing = ", ".join(_pg_text(row.get(column)) for column in _AUDIT_ROW_ORDER)
    return _pg_error(
        asyncpg.exceptions.CheckViolationError,
        f'new row for relation "audit_events" violates check constraint "{constraint}"',
        table="audit_events",
        constraint=constraint,
        detail=f"Failing row contains ({failing}).",
    )


@functools.cache
def audit_metadata_check_amended() -> bool:
    """Whether a shipped migration after 0005 re-adds ``audit_events_metadata_check``.

    The migrations next to the ``admino.database`` that is imported (the
    module's own directory, not the patchable ``_MIGRATIONS_DIR``), comments
    removed. False: the database holds 0005's CHECK, which refuses every array
    value (GH-189 security audit F1).
    """
    from admino import database

    directory = Path(database.__file__).parent / "migrations"
    for path in sorted(directory.glob("*.sql")):
        match = re.match(r"(\d{4})_", path.name)
        if match is None or int(match.group(1)) <= 5:
            continue
        sql = _SQL_COMMENT_RE.sub(" ", path.read_text(encoding="utf-8"))
        if _ADD_METADATA_CHECK_RE.search(re.sub(r"\s+", " ", sql).lower()):
            return True
    return False


def _audit_metadata_valid(text: str, *, amended: bool) -> bool:
    """``audit_events_metadata_check`` on the bound metadata JSON text.

    0005 (``amended=False``): an object of at most 4096 bytes and 16 keys
    matching ``^[a-z][a-z0-9_]{0,39}$``, no object or array value, every string
    value a ``^[a-z0-9_-]{1,64}$`` token. Amended (contract Amendment A1, as
    verified on postgres:16-alpine): at most 8192 bytes; ``attachment_ids`` is
    exempt from the value rule and, when present, must be an array of 1 to 100
    strings matching the canonical lowercase UUID regex.
    """
    # octet_length(metadata::text): the bytes of the jsonb text form, which
    # _jsonb_text approximates (jsonb key order, duplicate keys collapsed).
    stored = _jsonb_text(text)
    metadata = json.loads(stored)
    if type(metadata) is not dict:
        return False
    limit = _AUDIT_METADATA_BYTES_AMENDED if amended else _AUDIT_METADATA_BYTES_0005
    if len(stored.encode()) > limit or len(metadata) > _AUDIT_METADATA_KEYS_MAX:
        return False
    if any(_AUDIT_METADATA_KEY_RE.fullmatch(key) is None for key in metadata):
        return False
    for key, value in metadata.items():
        if amended and key == _AUDIT_ATTACHMENT_IDS_KEY:
            continue
        if isinstance(value, dict | list):
            return False
        if type(value) is str and _AUDIT_METADATA_TOKEN_RE.fullmatch(value) is None:
            return False
    if not amended or _AUDIT_ATTACHMENT_IDS_KEY not in metadata:
        return True
    ids = metadata[_AUDIT_ATTACHMENT_IDS_KEY]
    return (
        type(ids) is list
        and 1 <= len(ids) <= _AUDIT_ATTACHMENT_IDS_MAX
        and all(type(item) is str and _AUDIT_UUID_TEXT_RE.fullmatch(item) for item in ids)
    )


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
    if isinstance(value, list):
        # GH-189: an array as array_out prints it ({a,b}, NULL elements as NULL).
        return "{" + ",".join("NULL" if item is None else _pg_text(item) for item in value) + "}"
    return str(value)


def _included_attachment_ids_valid(role: Any, ids: list[Any] | None) -> bool:
    """Migration 0029's ``CHAT_INCLUDED_ATTACHMENTS_CHECK`` (GH-189), as PostgreSQL reads it.

    ``included_attachment_ids IS NULL OR (role = 'assistant' AND
    array_ndims(included_attachment_ids) = 1 AND cardinality(included_attachment_ids)
    >= 1 AND array_position(included_attachment_ids, NULL) IS NULL)``: NULL passes;
    a non-assistant row, an empty array (``'{}'``: no dimensions, cardinality 0), a
    multidimensional array and an array holding a NULL element are refused
    (verified on postgres:16-alpine).
    """
    if ids is None:
        return True
    return (
        role == "assistant"
        and len(ids) >= 1
        and not any(isinstance(item, list) for item in ids)
        and all(item is not None for item in ids)
    )


def _array_iterable(value: Any) -> bool:
    """What asyncpg's array encoder takes as an array: a sized iterable that isn't a
    str, bytes, bytearray, memoryview or mapping."""
    return (
        isinstance(value, Sized)
        and isinstance(value, Iterable)
        and not isinstance(value, str | bytes | bytearray | memoryview | Mapping)
    )


def _sub_array(value: Any) -> bool:
    """An element asyncpg reads as a sub-array (GH-189): an array iterable but a tuple
    (a nested tuple is a record for asyncpg)."""
    return _array_iterable(value) and not isinstance(value, tuple)


def _array_shape_error(value: Any) -> str | None:
    """asyncpg's ``_get_array_shape`` check (GH-189): sub-arrays of one length, never
    mixed with scalars ("non-homogeneous array"); None when the shape is fine."""
    length = -2
    for item in value:
        if _sub_array(item):
            if length == -2:
                length = len(item)
                if (error := _array_shape_error(item)) is not None:
                    return error
            elif len(item) != length:
                return "non-homogeneous array"
        elif length >= 0:
            return "non-homogeneous array"
        else:
            length = -1
    return None


def _flat(elements: Iterable[Any]) -> list[Any]:
    """The elements of a possibly multidimensional array (GH-189: ANY scans them all)."""
    flat: list[Any] = []
    for element in elements:
        if isinstance(element, list):
            flat.extend(_flat(element))
        else:
            flat.append(element)
    return flat


def _text_cast(value: Any) -> str | None:
    """``<expr>::text`` (GH-189): a uuid in its canonical text, an int's digits, a
    boolean as true / false; NULL stays NULL."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, uuid.UUID):
        return str(uuid.UUID(int=value.int))
    assert isinstance(value, int | Decimal), f"the fake can't cast {value!r} to text"
    return str(value)


def _failing_row(table: str, row: dict[str, Any]) -> str:
    """PostgreSQL's "Failing row contains (...)" detail: every column, each value
    cut to 64 bytes. Like the real driver's, it carries the row's content."""
    fields = []
    for column in _chat_types(table):
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

    GH-187: ``int4`` / ``int8`` also refuse an int outside int32 / int64 ("value
    out of int32 range"); an array kind (``uuid[]``) takes a sized iterable that
    isn't a str, bytes or mapping (a list, tuple, set ...), each element through
    the element kind's encoder (None allowed), and returns a list. GH-189: nested
    sized iterables (not tuples) of one length are a multidimensional array (a
    list of lists); sub-arrays of different lengths, or mixed with scalars, are a
    DataError ("non-homogeneous array"), as asyncpg's shape check refuses them.
    """
    if value is None:
        return None
    valid = True
    reason = f"{kind} expected"
    stored = value
    if kind.endswith("[]"):
        valid = _array_iterable(value)
        if not valid:
            reason = f"a sized iterable container expected (got type {type(value).__name__!r})"
        elif (shape := _array_shape_error(value)) is not None:
            # GH-189: nested lists of one length are a multidimensional array.
            valid, reason = False, shape
        else:
            return [
                _encode_chat_value(kind, position, item)
                if _sub_array(item)
                else _encode_chat_value(kind[:-2], position, item)
                for item in value
            ]
    elif kind == "uuid":
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
    elif kind in {"int4", "int8"}:
        bits = 32 if kind == "int4" else 64
        valid = type(value) is int
        if valid and not -(2 ** (bits - 1)) <= value < 2 ** (bits - 1):
            valid, reason = False, f"value out of int{bits} range"
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
    types = _chat_types(table)
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
    for table in _CHAT_TYPES:
        if re.search(rf"\b{table}\b", masked):
            columns.update(_chat_types(table))
    found: dict[int, str] = {}

    def note(
        number: str, column: str | None, cast: str | None = None, *, array: bool = False
    ) -> None:
        kind = _CAST_TYPES.get(cast) if cast else None
        if kind is None and column is not None:
            kind = columns.get(column)
        if kind is not None:
            found.setdefault(int(number), kind + "[]" if array else kind)

    # GH-187: an array cast (``$n::uuid[]``) types the parameter as an array.
    for match in re.finditer(r"\$(\d+) ?:: ?(\w+)( ?\[ ?\])?", masked):
        note(match.group(1), None, match.group(2), array=match.group(3) is not None)
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
    # GH-190 (A11): ``coalesce($n, col)`` / ``coalesce(col, $n)`` types $n as the
    # column (coalesce's arguments resolve to one common type, the column's).
    for match in re.finditer(
        r"(?<![\w.])coalesce ?\( ?\$(\d+)(?: ?:: ?\w+)? ?, ?(?:\w+\.)?(\w+) ?\)", masked
    ):
        note(match.group(1), match.group(2))
    for match in re.finditer(r"(?<![\w.])coalesce ?\( ?(?:\w+\.)?(\w+) ?, ?\$(\d+) ?\)", masked):
        note(match.group(2), match.group(1))
    if limit := re.search(r"\blimit \$(\d+)", masked):
        found.setdefault(int(limit.group(1)), "int")
    if head := re.match(r"insert into (\w+) ?\(([^)]*)\)", masked):
        table_types = _chat_types(head.group(1)) if head.group(1) in _CHAT_TYPES else {}
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


def _refuse_missing_active(n: str) -> None:
    """GH-190: before a shipped migration adds ``attachments.active``, a statement on
    attachments that names ``active`` (outside literals) is UndefinedColumnError.

    PostgreSQL refuses it when the statement is parsed, before any argument is
    encoded and whatever rows the tables hold (the reader alone would only fail
    once it evaluates the column, so an empty table would answer).
    """
    if shipped_schema().attachments_active:
        return
    masked = _masked_literals(n)
    if re.search(r"\battachments\b", masked) and re.search(r"\bactive\b", masked):
        msg = f'column "{ATTACHMENT_ACTIVE_COLUMN}" does not exist'
        raise _pg_error(asyncpg.exceptions.UndefinedColumnError, msg, table="attachments")


def _refuse_missing_trash_group(n: str) -> None:
    """GH-194: before a shipped migration adds ``trash_group_id`` to chats / attachments, a
    statement on such a table that names it (outside literals) is UndefinedColumnError.

    Refused when the statement is parsed, like ``_refuse_missing_active``: before
    any argument is encoded and whatever rows the tables hold.
    """
    masked = _masked_literals(n)
    if not re.search(rf"\b{TRASH_GROUP_COLUMN}\b", masked):
        return
    for table in TRASH_GROUP_CHECKS:
        if re.search(rf"\b{table}\b", masked) and table not in shipped_schema().trash_group_tables:
            msg = f'column "{TRASH_GROUP_COLUMN}" does not exist'
            raise _pg_error(asyncpg.exceptions.UndefinedColumnError, msg, table=table)


def _check_chat_binds(n: str, args: tuple[Any, ...]) -> None:
    """What asyncpg and PostgreSQL check before a chat-table statement runs.

    The argument count (InterfaceError, asyncpg's text) and no gap in the
    ``$n`` numbering (IndeterminateDatatypeError); each typed parameter through
    asyncpg's encoder (DataError); every str argument through the server's text
    input (U+0000: CharacterNotInRepertoireError), used or not; then the
    grants of migration 0024: admino_app may not DELETE chats (GH-194: until a
    shipped GRANT, 0032's, allows it; ``ShippedSchema.delete_tables``) and may
    not UPDATE or DELETE chat_messages (InsufficientPrivilegeError); and those of
    migration 0025 (GH-266): an UPDATE of chats may SET only the shipped
    column grant (``CHAT_UPDATE_COLUMNS`` until 0032 adds trash_group_id; another
    existing column: InsufficientPrivilegeError;
    a column chats doesn't have is left to the reader's UndefinedColumnError,
    which PostgreSQL raises first). GH-271: every column of a row-constructor
    piece ``(a, b, ...) = ...`` (a row, ``ROW(...)`` or a sub-select) is
    checked too, as PostgreSQL does. GH-187 (migration 0027): an UPDATE of
    attachments may SET only the ``ATTACHMENT_UPDATE_COLUMNS``, checked the
    same way ("permission denied for table attachments"); INSERT, SELECT and
    DELETE on attachments are granted.
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
        r"(?:delete from (?:only )?(?:public\.)?(chats|chat_messages|attachments)"
        r"|update (?:only )?(?:public\.)?(chat_messages))\b",
        n,
    )
    if denied is not None and (
        denied.group(2) is not None or denied.group(1) not in shipped_schema().delete_tables
    ):
        # GH-194: DELETE follows the shipped GRANTs (0027's attachments; 0032 adds chats).
        msg = f"permission denied for table {denied.group(1) or denied.group(2)}"
        raise asyncpg.exceptions.InsufficientPrivilegeError(msg)
    if (granted := _GRANTED_UPDATE_RE.match(n)) is not None:
        # GH-187: attachments has a column grant too (migration 0027).
        table = granted.group(1)
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
                if column in _chat_types(table) and column not in _update_grant(table):
                    msg = f"permission denied for table {table}"
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
            # PostgreSQL names an unaliased item after its outermost function
            # (GH-187: "coalesce" for coalesce(sum(x), 0)).
            name = re.match(r"(\w+)", expr)
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


def _numeric_sum(expr: str) -> bool:
    """True for ``sum(<a BIGINT expression>)``: PostgreSQL's sum(bigint) is NUMERIC.

    GH-187: a BIGINT column; GH-188 (A4' / A7'): also an expression whose type is
    BIGINT, e.g. ``size_bytes + coalesce(derived_bytes, 0)``.
    """
    match = re.fullmatch(r"sum ?\((.+)\)", _unwrap(expr))
    return match is not None and _bigint_expr(match.group(1))


def _bigint_expr(expr: str) -> bool:
    """True when PostgreSQL types an expression BIGINT (GH-188).

    A BIGINT column (``_BIGINT_COLUMNS``, optionally qualified); ``a + b`` / ``a - b``
    with a BIGINT operand (integer + bigint is bigint); ``coalesce(...)`` with a
    BIGINT argument (an integer constant beside it resolves to bigint).
    """
    expr = _unwrap(expr)
    if re.fullmatch(r"(?:\w+\.)?\w+", expr):
        return expr.rsplit(".", 1)[-1] in _BIGINT_COLUMNS
    if (binary := _binary_split(expr)) is not None:
        return _bigint_expr(binary[0]) or _bigint_expr(binary[2])
    if match := re.fullmatch(r"coalesce ?\((.+)\)", expr):
        return any(_bigint_expr(item) for item in _top_split(match.group(1), ","))
    return False


def _assert_evaluable(text: str) -> None:
    """Fail the test for a WHERE / ON text with a construct the reader doesn't evaluate.

    GH-187: ``<expr> = ANY(<array>)`` (or ``<>``) is evaluated; any other ANY isn't.
    """
    masked = re.sub(r"(?:=|<>|!=) ?any ?\(", "= (", _masked(text))
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
        if match := re.fullmatch(r"\$(\d+)(?: ?:: ?\w+(?: \w+)?(?: ?\[ ?\])?)?", expr):
            # GH-187: ``$n::uuid[]`` too (the bound sequence, already encoded-checked).
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
        if match := re.fullmatch(r"((?:\w+\.)?\w+|\( *\)) ?:: ?(?:text|varchar)", _masked(expr)):
            # GH-189: ``a.id::text``, ``a.page_count::text`` (T2'): the value's text,
            # NULL stays NULL. ``::`` binds tighter than any operator, so the cast
            # applies to a column or a parenthesized expression only.
            return _text_cast(self.value(expr[: match.end(1)], ctx))
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
        return self.derived[table] if table in self.derived else _table_columns(table)

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
        if match := re.fullmatch(r"(.+?) ?(=|<>|!=) ?any ?(\( *\))", masked):
            # GH-187: ``col = ANY($n::uuid[])``. A NULL array or left side, or no
            # matching element (NULL elements never match), is not true.
            left = self.value(atom[: match.end(1)], ctx)
            inner = atom[match.start(3) + 1 : -1].strip()
            assert not inner.startswith("select "), f"the fake doesn't do ANY(SELECT): {atom}"
            elements = self.value(inner, ctx)
            if left is None or elements is None:
                return False
            assert isinstance(elements, Iterable) and not isinstance(elements, str), atom
            return any(
                element is not None and _compare(match.group(2), left, element)
                for element in _flat(elements)
            )
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
        and constants; an optional trailing cast is ignored, except that an
        integer cast turns a NUMERIC value into an int.

        GH-187: ``sum(col)`` is NULL over no non-NULL input; over a BIGINT column
        (``_BIGINT_COLUMNS``) it is NUMERIC, a ``Decimal`` as asyncpg decodes it,
        and so is a ``coalesce`` holding such a sum (its constant included), as on
        postgres:16.
        """
        expr = _unwrap(expr)
        cast = re.fullmatch(r"(.+?) ?:: ?(\w+)", _masked(expr))
        if cast is not None:
            value = self.aggregate(expr[: cast.end(1)], contexts)
            if isinstance(value, Decimal) and _CAST_TYPES.get(cast.group(2)) == "int":
                return int(value.to_integral_value(rounding=ROUND_HALF_UP))
            return value
        if match := re.fullmatch(r"sum ?\((.+)\)", expr):
            inner = match.group(1).strip()
            present = [value for ctx in contexts if (value := self.value(inner, ctx)) is not None]
            assert all(
                isinstance(value, int | Decimal) and not isinstance(value, bool)
                for value in present
            ), f"sum of non-numbers: {expr!r}"
            if not present:
                return None
            total = sum(present)
            return Decimal(total) if _numeric_sum(expr) else total
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
            items = _top_split(match.group(1), ",")
            numeric = any(_numeric_sum(item) for item in items)
            for item in items:
                value = self.aggregate(item, contexts)
                if value is not None:
                    if numeric and type(value) is int:
                        return Decimal(value)
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
        if re.search(r"(?<![\w.])union(?!\w)", masked):
            return self.union(n)
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
        unsupported = {"group by", "having", "offset"}
        assert not unsupported & clauses.keys(), f"the fake can't read this SELECT: {n}"
        if "from" not in clauses:
            # GH-157: a FROM-less SELECT (a computed digest) is one row of values.
            assert set(clauses) == {"select"}, f"a SELECT without FROM: {n}"
            return self.project(clauses["select"], [{}])
        assert not clauses["select"].startswith("distinct"), "no DISTINCT in the fake"
        # Every row-lock strength is recorded with no effect (GH-187: FOR SHARE on chats,
        # FOR NO KEY UPDATE on organizations); none is allowed with an aggregate.
        locks = [
            lock
            for lock in ("for update", "for no key update", "for share", "for key share")
            if lock in clauses
        ]
        if locks and _AGGREGATE_RE.search(_masked_literals(clauses["select"])):
            msg = f"{locks[0].upper()} is not allowed with aggregate functions"
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

    def union(self, n: str) -> list[dict[str, Any]]:
        """``SELECT ... UNION [ALL] SELECT ... [ORDER BY <output column>, ...] [LIMIT $n]``.

        GH-194 (J1). Left-associative, as in PostgreSQL: each UNION removes
        duplicate rows from everything before it (NULLs equal), UNION ALL keeps
        them. The columns are named by the first SELECT; every SELECT must have
        as many (PostgresSyntaxError otherwise). A trailing ORDER BY / LIMIT
        applies to the whole result and may name output columns only; any other
        ORDER BY or LIMIT, or a row lock, fails the test. Without ORDER BY the rows
        come back reversed (PostgreSQL promises no order).
        """
        masked = _masked(n)
        parts: list[str] = []
        keep_all: list[bool] = []
        start = 0
        for match in re.finditer(r" union( all)? ", masked):
            parts.append(n[start : match.start()].strip())
            keep_all.append(match.group(1) is not None)
            start = match.end()
        last = n[start:].strip()
        tail = re.search(r"(?<![\w.])(?:order by|limit)(?!\w)", _masked(last))
        parts.append(last[: tail.start()].strip() if tail is not None else last)
        trailing = _clauses(last[tail.start() :], ("order by", "limit")) if tail else {}
        for part in parts:
            part_masked = _masked(part)
            assert part.startswith("select "), f"the fake can't read this UNION part: {part}"
            assert not re.search(
                r"(?<![\w.])(?:order by|limit|offset|for (?:update|no key update|share|key"
                r" share))(?!\w)",
                part_masked,
            ), f"the fake reads ORDER BY / LIMIT after the last UNION part only: {n}"
        names = [
            [name for _, name, _ in _select_items(_clauses(part, ("select", "from"))["select"])]
            for part in parts
        ]
        if len({len(listed) for listed in names}) != 1:
            msg = "each UNION query must have the same number of columns"
            raise asyncpg.exceptions.PostgresSyntaxError(msg)
        rows: list[dict[str, Any]] = []
        for index, part in enumerate(parts):
            rows += [dict(zip(names[0], row.values(), strict=True)) for row in self.select(part)]
            if index > 0 and not keep_all[index - 1]:
                distinct: dict[tuple[Any, ...], dict[str, Any]] = {}
                for row in rows:
                    distinct.setdefault(tuple(_canonical(value) for value in row.values()), row)
                rows = list(distinct.values())
        key = f"union:{n}"
        self.derived[key] = frozenset(names[0])
        contexts: list[_Context] = [{key: (key, row)} for row in rows]
        if "order by" in trailing:
            for piece in _top_split(trailing["order by"], ","):
                column = re.fullmatch(r"(\w+)(?: (?:asc|desc))?(?: nulls (?:first|last))?", piece)
                assert column is not None and column.group(1) in names[0], (
                    f"the fake orders a UNION by its output columns only: {n}"
                )
            contexts = self.ordered(contexts, trailing["order by"])
        else:
            contexts = contexts[::-1]
        result = [kept for ctx in contexts if (kept := ctx[key][1]) is not None]
        if "limit" in trailing:
            result = result[: self.limit(trailing["limit"])]
        return result

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
        """An INSERT into chats, chat_messages or (GH-187) attachments (see the module docstring).

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
        unknown = set(columns) - _table_columns(table)
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
            if match.group(1) not in _table_columns(table):
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
    """The pool: statements run outside any transaction; acquire() yields a connection.

    ``acquire`` takes the keyword-only ``timeout`` of asyncpg's ``Pool.acquire``
    (GH-278 Decision 4: ``database.TimedPool.acquire`` always passes it, ``None``
    included); the fake never waits for a free connection, so it is ignored.
    """

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
    async def acquire(self, *, timeout: float | None = None) -> AsyncIterator[FakeConnection]:
        yield self._db.new_connection()
