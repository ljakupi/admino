"""FastAPI web server for admino — the HTTP/SSE boundary layer.

Exposes the REST API, with the chat turns streamed as server-sent events on
request (GH-8), that clients interact with. All user input enters through this
module and all responses leave through it. The server is a thin HTTP layer
that delegates business logic to the agent.

Routes:
- POST /api/auth/login    — Email/password login; sets the session cookie (public).
- POST /api/auth/password-reset — Emails a password reset link; always 202 (public).
- POST /api/auth/password-reset/confirm — Sets a new password with a reset link's
  token, ends every session of the account, clears the cookie (public).
- GET  /api/auth/invitations/{token} — The org name, role and email of a usable
  invitation link (public).
- POST /api/auth/invitations/{token}/accept — Accepts an invitation with a name
  and password; activates the account and sets the session cookie (public).
- POST /api/auth/logout   — Ends (deletes) the current session and clears the cookie.
- GET  /api/auth/me       — The logged-in account (from the resolved session).
- GET  /api/me/sessions   — The caller's live sessions, the current one marked.
- DELETE /api/me/sessions/{session_id} — Ends one of the caller's sessions
  (clears the cookie when it is the current one); audited.
- GET/PATCH /api/me       — The caller's own name, languages, timezone and
  personal instructions (every role).
- POST /api/me/password   — Changes the caller's own password, ends every
  session of the caller and clears the cookie; audited.
- POST /api/org/users/{user_id}/logout — An Org Admin ends every session of a
  user of their org; audited.
- GET  /api/org/users     — The active and deactivated users of the caller's org.
- PATCH /api/org/users/{user_id} — Changes a user's role, name or email; audited.
- POST /api/org/users/{user_id}/deactivate, .../reactivate — Deactivates (ending
  every session of the user) or reactivates a user of the org; audited.
- DELETE /api/org/users/{user_id} — Deletes a user with their sessions,
  connections and notes (clears the cookie when it is the caller); audited.
- POST /api/org/users/{user_id}/password-reset — Emails a user of the org a
  password reset link; audited.
- POST /api/org/invitations — An Org Admin invites an email into their org; audited.
- GET  /api/org/invitations — The pending invitations of the caller's org.
- DELETE /api/org/invitations/{invitation_id} — Revokes a pending invitation
  (deletes the invited account); audited.
- POST /api/org/invitations/{invitation_id}/resend — Sends a pending invitation
  again with a new link; audited.
- GET  /api/platform/orgs — Every organization's metadata (Super Admin).
- POST /api/platform/orgs — Creates an organization and invites its first Org
  Admin (Super Admin); audited.
- PATCH /api/platform/orgs/{org_id}/limits — Changes an org's plan limits;
  audited.
- POST /api/platform/orgs/{org_id}/deactivate, .../reactivate — Deactivates
  (ending every session of its users) or reactivates an org; audited.
- POST /api/platform/orgs/{org_id}/deletion — Schedules an org's deletion after
  the grace period (its active Org Admins are emailed); audited.
- DELETE /api/platform/orgs/{org_id}/deletion — Cancels a pending deletion (the
  org stays deactivated); audited.
- PATCH /api/platform/orgs/{org_id}/residency — Sets an org's data residency
  policy; audited in the org's own log.
- GET  /api/platform/orgs/{org_id}/users — An org's active, deactivated and
  invited accounts (Super Admin).
- GET  /api/platform/orgs/{org_id}/metadata — An org's seat usage, storage
  used and chat and file counts (Super Admin).
- POST /api/platform/orgs/{org_id}/users/{user_id}/deactivate, .../reactivate
  — Deactivates (ending every session of the user) or reactivates a user of
  the org (Super Admin); audited in the org's own log.
- POST /api/platform/orgs/{org_id}/users/{user_id}/password-reset — Emails a
  user of the org a password reset link (Super Admin); audited in the org's
  own log.
- POST /api/platform/orgs/{org_id}/users/{user_id}/invitation — Resends or
  replaces the invitation of an org's invited Org Admin while the org has no
  active one (Super Admin); audited in the org's own log.
- GET  /api/platform/diagnostics — The database status, the active LLM provider
  and model, and whether the LLM looks reachable (Super Admin).
- POST /api/chats         — Creates a chat of the caller (201 ChatSummary).
- GET  /api/chats         — One page of the caller's chats, latest activity
  first (``limit``, ``cursor``).
- GET  /api/chats/{chat_id} — The chat's summary, one page of its messages
  (the latest first, ``cursor`` to earlier ones), its confirmation state and
  context.
- PATCH /api/chats/{chat_id} — Renames the chat.
- DELETE /api/chats/{chat_id} — Moves the chat to the trash (204); audited.
- POST /api/chats/{chat_id}/messages — Runs a turn in the chat; returns
  ChatResponse (with the run's LLM error code, GH-242, or ``rate_limit`` when
  the caller's pending-confirmation limit refused its confirmation, GH-24),
  or, with ``Accept: text/event-stream``, streams the run as server-sent
  events (GH-8). The first exchange of an untitled chat titles it after the
  response (GH-179; a streamed one before its ``done``). 409 ``run_active``
  while a run of the chat is going. GH-187: ``attachment_ids`` sends the
  caller's unsent uploads of the chat with the message (linked to the stored
  user message).
- POST /api/chats/{chat_id}/stop — Stops the chat's streamed run
  (``{"stopped": bool}``, GH-8).
- POST /api/chats/{chat_id}/attachments — Stores one file (the raw request
  body, its name in ``X-Attachment-Name``) in a chat of the caller (201
  AttachmentSummary, GH-187); audited.
- GET  /api/attachments/{attachment_id} — An attachment's metadata and
  processing status (the chat's owner only).
- GET  /api/attachments/{attachment_id}/content — Downloads the stored
  original (the chat's owner only).
- POST /api/message       — Legacy: a turn in the caller's chat of a client
  ``session_id`` (created by its first run, until #177: a refused first
  message creates none); returns ChatResponse, always JSON. Titles the chat
  and refuses a busy one like the route above.
- POST /api/confirm/{cid} — Approve or deny a pending confirmation of a chat
  (``chat_id``, or the legacy ``session_id``); returns ChatResponse (with the
  resumed run's LLM error code), or streams like a turn (GH-8).
- GET/PATCH /api/me/settings — The caller's own theme and notifications (every
  role).
- POST /api/me/settings/reset — Revert the caller's own settings to the
  defaults (every role).
- GET/PATCH /api/org/settings — The Org Admin's own org's profile,
  instructions, session policy (applied to the org's open sessions), trash
  retention (within the platform's bounds) and tool services, with the data
  residency and plan read-only; audited.
- GET/PATCH /api/platform/settings — The platform defaults: LLM (with the
  model capabilities, the retry limit and the number of residency orgs),
  limits, files, retention and security (Super Admin); audited. A switch to a
  non-Swiss provider needs the residency-org count confirmed (409
  ``residency_confirmation`` otherwise).
- GET/PATCH /api/org/permissions — The Org Admin's own org's tool permission
  matrix; a change is audited.
- GET  /api/org/critical-permissions — The org's four promotable (tier-2)
  permissions, with their state and pending promotion.
- PATCH /api/org/critical-permissions/{tool}/{action} — Demotes a promoted
  pair at once, or (with the Org Admin's password) starts its 5-minute
  promotion cooldown; audited.
- DELETE /api/org/critical-permissions/{tool}/{action}/pending — Cancels a
  pending promotion; audited.
- GET  /api/permissions/summary — The effective state of each of the caller's
  org's tool actions (read-only, every member role).
- GET  /api/oauth/{google,microsoft}/authorize — The consent URL to connect the
  caller's own account; binds the state to the caller's session and sets the
  ``admino_oauth_state`` cookie.
- GET  /api/oauth/{google,microsoft}/status — The caller's own connection, the
  org's switches of the provider's services and the org's data residency.
- DELETE /api/oauth/{google,microsoft} — Revokes and deletes the caller's own
  connection.
- GET  /health            — Health check (public): ``{"status": "ok"}``, or 503
  ``{"status": "degraded"}`` when the database is unreachable; nothing else.
- GET  /api/oauth/callback — The OAuth provider's redirect (public; checks the
  state, its binding cookie and the initiating session).
- /                       — Static PWA files (public); a missing client route
  (outside /api and /health, last segment without an extension) gets
  index.html for the PWA's router. Hashed assets (``assets/<name>-<hash>.<ext>``)
  are ``Cache-Control: public, max-age=31536000, immutable``; everything else
  the mount serves is ``no-cache`` (GH-244).

Security notes:
- Authentication is a server-side session (GH-149): the ``admino_session``
  cookie (HttpOnly, SameSite=Strict, Path=/, Secure unless
  ``server.cookie_secure`` is off) carries an opaque token that
  ``sessions.resolve_session`` checks against the database on every request,
  re-reading the account, so a deactivated user or org is refused at once.
  A session ends after its idle timeout or at the end of its lifetime (its
  policy, GH-152); the cookie's Max-Age is that lifetime. Ending a session
  deletes its row, so the cookie is refused on its next request.
  Every route except the public ones above depends on ``require_session``; the
  ``Principal`` always comes from the session row, never from request data.
  There is no bearer-token or VPN mode, and ``Authorization`` headers
  authenticate nothing.
- The chat routes also need ``Capability.CHAT_SEND`` (403 for a Viewer or a
  Super Admin, before any database work); the principal is passed to
  ``agent.run``.
- Persisted chats (GH-176, ``admino.chats``): chats are private to their
  owner. Every statement binds the caller's org and user id (from the
  session, never a request value), so an unknown id, another org's chat, a
  colleague's chat (an Org Admin's request included) and a trashed chat
  answer the same 404 ``{"detail": "Chat not found", "reason":
  "chat_not_found"}`` with nothing changed. Each route spends a per-user
  bucket; a chat turn spends the ``/api/message`` bucket shared with the
  legacy route, so alternating routes doesn't double the LLM rate. A cursor
  that doesn't decode is a 422 ``invalid_cursor``; no error repeats a title,
  message or cursor. A turn runs on the latest ``max_context_messages``
  messages (``chats.load_turn``, with the chat) and passes the chat's sticky
  ``external_content`` flag, read under the chat's lock (an approval that
  waited for a running turn gets what that turn stored), as
  ``earlier_external_content`` (GH-243 covers the whole conversation); its new
  messages are stored after the run (an agent failure stores nothing; a chat
  trashed meanwhile is the 404). A denial is stored too (the closing ``tool``
  results and the assistant's denial), so the history stays well-formed. The
  agent's ``session_id`` is ``str(chat.id)``, so ``tool.call`` rows target
  the chat. Trashing records
  ``chat.delete`` in the same transaction. The legacy ``session_id`` names
  the caller's own chat (``chats.legacy_session_id``): another user's
  session id is a chat of the caller's own, and a confirmation never creates
  one. Log lines name chat ids only: never a title, message text or legacy
  session id.
- Pending confirmations (GH-24): one expires ``confirmation_timeout_s`` (the
  stored platform limit) after its creation, by ``_utc_now``. Expired ones
  are reaped at the start of every chat request and every
  ``_CONFIRMATION_REAP_INTERVAL_S`` by a background task (memory only: no
  query, no chat lock), and are never dispatched: confirming one, including
  one that expires while the request waits for the chat's lock, is the 404
  "No pending confirmation for this session" with nothing run or stored. A
  user holds at most the stored ``max_pending_confirmations`` (read per
  request) in their other chats: a run (a turn or an approved resume) asking
  for one more keeps nothing, is stored with that call's "too many
  confirmations are pending" result (any other dangling call cancelled) and
  a reply, and answers 200 ``status: "error"``, ``error_code: "rate_limit"``
  (not a 429: the turn already ran and is stored). Other users and orgs never
  count.
- Automatic titles (GH-179, ``admino.chat_titles``): after the first
  exchange of an untitled ``auto`` chat, a background task (after the
  response, no chat lock) sends the first message and the reply only (as
  written, each cut to 1,000 characters; no tools, no account identifiers)
  through ``llm_policy.chat`` (the org's residency guard, the stored retry
  limit) to the client running at that moment, and stores the sanitized
  title by compare-and-set (``chats.set_auto_title``), so a rename always
  wins. A failed call, a blocked provider or an ``error`` run (a
  confirmation refused with ``rate_limit`` included, GH-24) stores the
  fallback (the first message, sanitized). So does a first run whose tool
  results hold wrapped external content (GH-243; the same rule as the chat's
  sticky ``external_content`` flag), with no model call: an email, file or
  page the reply quotes never chooses the title. GH-8: a streamed first
  exchange is titled by its run task after ``message_saved`` (no chat lock;
  a ``stopped`` turn also gets the fallback, with no model call) and sends
  the stored automatic title as ``title`` before ``done``. No audit event;
  titles aren't logged.
- Streamed turns (GH-8, ``admino.event_stream``, ``admino.streaming``): the
  turn route and the confirm route answer server-sent events when the
  ``Accept`` header lists ``text/event-stream`` with a ``q`` above 0 (the
  legacy POST /api/message never does). Every check before the run (401,
  CSRF 403, 403, 404, 409, 422, 429, 503) is the usual JSON error; the
  stream starts once the run holds its chat. The run executes in a detached
  task (kept referenced until it ends) that stores the turn, frees the chat,
  and only then sends ``confirm`` / ``message_saved`` / ``error``, the title
  and ``done``; an agent that raised is ``error{internal_error}`` and a chat
  trashed meanwhile ``error{chat_not_found}``, with nothing stored. Frames
  are built through ``SSEEvent`` (``_make_sse_event``): one line of JSON
  each (no raw CR/LF, no NaN/Infinity literal), a validated event name.
  ``delta`` texts are display text (``streaming.DisplayDeltas``: the JSON
  reply's cleanup and credential redaction, word by word, a trailing
  ``Bearer`` held for the next word), so a key never streams in part; an
  answer that doesn't complete (a ``stopped`` or ``error`` run, an agent
  that raised, a chat trashed meanwhile, GH-25: a ``final`` run whose
  answer an output cap cut, ``AgentResult.truncated``) ends at its last
  ASCII whitespace, its unfinished last word (maybe a key cut short) never
  sent, as the agent's stored reply ends. A ``timeout`` after text stores
  that text, cut the same way, before the error reply, so the deltas end at
  the stored partial's last word and ``message_saved`` names the error
  reply. A ``malformed_response`` failure is reported like any coded LLM
  error (``error{malformed_response}``, never ``internal_error``).
  ``tool_call`` and ``confirm`` carry the JSON response's redacted items. A
  frame that can't be built is dropped (its event name and the exception
  class logged, never its payload) and the run goes on: building or queueing
  a frame never raises into the run. Frames queue in memory and nothing
  waits for the client: ``EventStreamResponse`` watches for its disconnect
  (also under ASGI 2.4, where Starlette doesn't), which sets the run's stop
  like the stop route; the run still ends by the agent's stop rules and is
  stored and titled. At shutdown the lifespan sets every detached run's stop
  and waits for them (at most ``_DRAIN_TIMEOUT_S``; the count of runs still
  going is logged) before it stops the background jobs and closes the pool,
  so a run whose client left still audits its tool call and stores its turn.
- One run per chat (GH-8): a message takes its chat with
  ``ChatRuntime.hold(wait=False)``: while a run of the chat is going it is
  the 409 ``{"detail": "A message is already running in this chat.",
  "reason": "run_active"}`` (after the rate limit, the 422 checks and the
  404), with nothing run or stored and the chat's pending confirmation
  untouched. A confirmation still waits for the chat (the running turn may
  store the confirmation it approves).
- Stop (GH-8): ``POST /api/chats/{chat_id}/stop`` needs ``chat.send`` (403
  before any database work), the CSRF check and its per-user bucket; the
  chat is read with the caller's tenant (the same 404 as the other chat
  routes), then ``ChatRuntime.request_stop`` sets the stop signal a streamed
  run registered (``stoppable``); it never creates a runtime entry, a JSON
  run can't be stopped, and no request body is read. A stop isn't audited
  (every tool call still is, as ``tool.call``); at most an INFO line names
  the chat id. No message, delta, title, tool argument or legacy session id
  is ever logged.
- Attachments (GH-187, ``admino.attachments``, ``admino.attachment_types``):
  the upload needs ``Capability.FILE_UPLOAD`` (Org Admin, Editor; 403 for a
  Viewer or a Super Admin before any database work or bucket), the reads
  ``Capability.CHAT_SEND``. Every check of the upload comes before a body
  byte is read, in this order: the per-user bucket (its burst is the
  platform ``max_files_per_message``, read when the bucket is created), the
  ``X-Attachment-Name`` header (``sanitize_filename``: percent-encoded ASCII
  of at most 4096 characters, else 400 ``invalid_filename``), a
  ``Content-Length`` of 1 to 18 digits (else 411 ``content_length_required``),
  then in ``attachments.upload_attachment`` the size (400 ``empty_file``, 413
  ``file_too_large`` above the platform ``max_file_size_mb`` MiB, read on
  every request), the chat's owner (the chat routes' 404 ``chat_not_found``)
  and the org's storage quota (413 ``storage_quota_exceeded``). The body
  (``request.stream()``) is then never read past its ``Content-Length`` (400
  ``content_length_mismatch`` either way; a client that leaves mid-body gets
  the same), the type comes from the content only (the declared
  ``Content-Type`` and the name's extension are ignored; 415
  ``unsupported_type`` / ``legacy_office``, 422 ``password_protected`` /
  ``corrupted_file``), and the commit checks the chat and the quota again
  under their locks; a disk failure is 503 ``storage_unavailable``. Every
  refusal is ``{"detail": <fixed text>, "reason": <code>}`` and stores no
  row, file or audit event. A stored file (``file.upload``, content-free) is
  submitted once to the bounded processing pool (``_processing``) after the
  commit. The reads answer the caller's own live attachment only: another
  org's, a colleague's (an Org Admin's request included), a trashed, an
  unknown one and a row whose file is gone are one 404
  ``attachment_not_found``. A download is the stored bytes with the kind's
  ``Content-Type``, ``Content-Disposition: attachment; filename*=UTF-8''...``
  (the percent-encoded download name, never a raw header value) and
  ``Cache-Control: no-store``; ``nosniff`` comes with every response. A
  message's ``attachment_ids`` above the platform ``max_files_per_message``
  is a 422 ``too_many_files`` before any attachment statement; after the
  chat's owner check, an id that isn't the caller's live file of the chat is
  the 404 ``attachment_not_found`` and a sent one the 409
  ``attachment_already_sent``, all before the run with nothing stored. Log
  lines carry ids, sizes and kinds only: never a file name, a header value or
  file bytes.
- Session management: ``/api/me/sessions`` needs ``Capability.ACCOUNT_MANAGE``
  and only ever reads or deletes the caller's own sessions; a forced logout
  needs ``Capability.ORG_USERS_MANAGE`` and only reaches users of the Org
  Admin's own org. Another user's session, or a user outside the org, is the
  same 404 as an unknown id. Path ids are typed as UUIDs: anything else is a
  422 that doesn't include the input value.
- Account self-service (GH-166, ``admino.my_account``): each route spends a
  per-user bucket, then needs ``Capability.ACCOUNT_MANAGE`` (every role, the
  Super Admin included) before any database work, and only ever reads or
  writes the caller's own users row (from the session, never a request
  value). The patch refuses unknown keys (email, role, org, kind) and a 422
  never echoes the input. A password change checks the policy first (a 422
  with its reason, nothing counted), then the current password through
  ``auth.reauthenticate`` (a wrong one counts in the login throttle like a
  failed login; a locked account or IP is refused; both are 403
  "Re-authentication failed.", never 401). It ends every session of the
  caller (the cookie is cleared) and is audited as ``password.change`` in the
  same transaction (a failed audit write is a 500 with nothing changed).
  Profile edits aren't audited. No password, name, email, timezone or
  instructions is logged.
- Invitations: sending, revoking and resending need
  ``Capability.ORG_USERS_INVITE``, listing ``Capability.ORG_USERS_VIEW``, and
  every statement is scoped to the Org Admin's own org: another org's
  invitation is the same 404 as an unknown id. The invited account's language
  is the caller's session language, never a request field. Invitation links
  are built from ``server.public_url`` only. The two public link routes answer
  one generic 404 for every link that can't be used (a malformed token, of any
  length, is a 404 before any token lookup, never a 422); accepting sets the
  session cookie exactly like the login. The email, name, password, token and
  link are never logged or echoed. The token travels in the URL path of the
  two link routes: uvicorn's access log stays off (``main.py``), and the
  bundled Caddy config of the production profile doesn't log request paths
  (a custom reverse proxy in front of admino must not either). A refused send
  (409 ``email_taken`` or ``seat_limit``) is audited and spends a separate,
  tighter per-user budget (``/api/org/invitations/refused``): once it's spent,
  sends answer 429 before any database work, so probing whether an email
  exists elsewhere on the platform stays slow and visible.
- Org Admin user management (GH-164, ``admino.org_users``): listing needs
  ``Capability.ORG_USERS_VIEW``, every change ``Capability.ORG_USERS_MANAGE``
  (a role change also ``Capability.ORG_USERS_ROLE_CHANGE``); each route spends
  a per-user bucket first (deactivate/reactivate share one). Every statement
  is scoped to the Org Admin's own org: another org's user, an invited or a
  deleted account is the same 404 as an unknown id. The last-admin guard is a
  409 ``last_admin``. A refused email change (409 ``email_taken``) spends the
  refused-send budget above, and a PATCH carrying an email answers 429 once
  it's spent, before any database work. Reset and login links are built from
  ``server.public_url`` only; the reset token never reaches the admin.
  Deactivating or deleting oneself clears the cookie. After a delete the
  server forgets the user's pending confirmations and chat locks
  (``ChatRuntime.forget_user``; the chats go with the users row), pending
  OAuth states and cached access tokens; a refused one forgets nothing. No
  name, email, token or link is logged.
- Platform organizations (GH-154): only a Super Admin reaches them, through
  ``access.can`` in ``admino.organizations`` (``org.create``,
  ``org.lifecycle.manage`` for the list and the status changes,
  ``org.limits.manage``, ``org.residency.manage``); every member role gets
  403, and the handlers pass the session's ``Principal``, never an
  ``access.Operator`` (only the admin CLI builds one). Responses carry org
  metadata only (operator blindness): the create response holds the
  InvitationSummary, never the token or the link. The first Org Admin gets
  the caller's session language, and the link is built from
  ``server.public_url`` only. A taken email is a 409 ``email_taken`` with
  nothing written; a change the org's status doesn't allow is a 409
  ``invalid_status``; an unknown org a 404; a failed audit write a 500 with
  nothing written. Each route spends a per-user bucket before any database
  work (deactivate/reactivate share one, as do schedule/cancel), and the org
  name, the admin email, the token and the link are never logged.
- Platform user administration (GH-167, ``admino.platform_users``): only a
  Super Admin reaches it, through ``access.can`` in the service
  (``platform.org_metadata.view`` for the users list and the metadata,
  ``platform.users.manage`` for the four actions); every member role gets
  403 before any query. Each route spends a per-user bucket first
  (deactivate/reactivate share one). The path's org scopes the user:
  another org's user, an unknown id, a deleted account and a Super Admin
  (the caller included) are the same 404. The reads are account metadata,
  counts and sizes only, and write and audit nothing. Every action is
  audited in the affected org's log (actor kind ``super_admin``); a failed
  audit write is a 500 with nothing changed. The last-admin guard applies
  (409 ``last_admin``). Reset and invitation links are built from
  ``server.public_url`` only and travel in the email only: no response
  carries a token or a link, and no route sets a password, changes an
  existing user's email or acts as another user. A re-invite with an email
  replaces only an invited account (in the caller's session language); it
  checks the refused-send budget above before any database work (429 once
  spent), and its ``email_taken`` or ``seat_limit`` refusal spends one token.
  No cookie is set or cleared, and no name, email, token or link is logged.
- Settings scopes (GH-159, ``admino.scoped_settings``): each route spends a
  per-user bucket, then checks its capability before any database work or
  provider probe: ``account.manage`` for /api/me/settings and its reset (the
  caller's own row only), ``org.settings.manage`` and
  ``org.instructions.manage`` for /api/org/settings (GH-169; both Org Admin
  only, the principal's own org only, never a request value),
  ``platform.defaults.manage`` for /api/platform/settings. Org and platform
  changes share one transaction with their audit events (a failed audit write
  is a 500 with nothing written); the platform llm event names the changed
  fields, never a provider or model value, the other sections' events carry
  old/new ints. The org events (one per changed section) name the changed
  profile fields and the instructions, never their values, and carry old/new
  ints for the session policy and the trash retention. A changed org session
  policy re-times the org's live sessions in the same transaction (an ended
  one is never revived). The org's data residency and plan are read-only (a
  patch naming them is a 422), and an org trash retention outside the
  platform's bounds is a 400 ``trash_retention_bounds`` with nothing written.
  A platform LLM switch builds the new client before anything is
  written (400 with nothing written when it can't be built) and closes the old
  one best-effort. A trash retention minimum above the maximum (merged with
  the stored values) is a 400 with nothing written. The platform response
  carries key presence flags, never a key, and no platform route returns an
  org's instructions.
- Model policy (GH-242, ``admino.llm_policy``): a PATCH switching the
  platform LLM to a provider outside ``llm_policy.SWISS_PROVIDERS``
  (infomaniak, vllm) needs ``confirm_residency_orgs`` equal to the current
  number of residency orgs (``organizations.count_residency_orgs``, every
  org status). Otherwise it is a 409 ``{"detail", "reason":
  "residency_confirmation", "residency_orgs"}``, checked after the rate
  limit and the capability (a member still gets 403) and before any client
  is built: nothing written, no audit event, the running client kept. A
  change of the model capabilities (``max_input_tokens``, ``image_input``) or
  the retry limit (``max_retries``) alone never rebuilds the client. The
  agent's residency guard blocks a residency org's run on a non-Swiss client
  before any LLM call or tool dispatch (``residency_blocked``). Chat
  responses carry the run's ``error_code`` (the PWA shows its translation);
  the response text is a user-facing error's fixed message or the generic
  reply, and no provider text or exception cause is ever logged or returned.
- Tool permissions per org (GH-161, ``admino.org_permissions``): each route
  spends a per-user bucket, then checks its capability before any database
  work: ``org.permissions.manage`` (Org Admin) for the matrix and the critical
  permissions, ``org.permissions.view`` (every member role, never the Super
  Admin) for the summary. Every read and write is the principal's own org,
  never a request value. A hardcoded denial (either tier, any value) and an
  unknown pair are 400s with nothing read or written. A promotion needs the
  Org Admin's own password (``auth.reauthenticate``: a wrong one counts in the
  login throttle like a failed login, a locked account or IP is refused) and
  then the cooldown; a demotion only reduces privilege, so it needs none. A
  failed audit write is a 500 with nothing changed; a 422 never echoes the
  password. Pending promotions live in process memory (a restart cancels
  them); an org's due ones are completed by that org's next chat run, summary
  or critical-permissions request, and a user-role notice (GH-66) is stored
  in every chat of that org that isn't in the trash and whose latest message
  doesn't await a confirmation (``chats.append_org_notice``, GH-24: it would
  split a ``tool_use`` from its result), never in another org's.
- OAuth connections are per user (GH-162): every OAuth route but the callback
  spends a per-user bucket, then needs ``Capability.OAUTH_CONNECT`` through
  ``access.can`` (Org Admin and Editor: 403 for a Viewer or a Super Admin)
  before any database work, and only ever reads, writes or deletes the
  caller's own ``oauth_tokens`` row (``TenantContext.from_principal``, never
  a request value). Under the org's data residency policy authorize is a 403
  with ``OAUTH_RESIDENCY_DETAIL`` and nothing stored; status still reports
  the kept (inactive) connection and disconnect still works. Authorize binds
  the state to the initiating user and session (``OAuthPendingState``) and
  sets the ``admino_oauth_state`` cookie (HttpOnly, SameSite=Lax,
  Path=/api/oauth/callback, Max-Age=600, Secure iff ``server.cookie_secure``).
  A user has at most one pending state (a new authorize replaces theirs) and
  no authorize ever evicts another user's, so no org can break another org's
  connect flow; expired states are reaped. The public callback pops the
  state first (one-shot), requires the cookie to equal it (constant time),
  then re-resolves the initiating session by id
  (``sessions.resolve_session_by_id``, which never refreshes it) and
  re-checks ``oauth.connect`` and residency before any token-endpoint call;
  the token is stored for the initiating user only, nothing is stored on any
  error, and every redirect deletes the cookie. Connecting and disconnecting
  invalidate that user's cached access token (``oauth.access_tokens``). No
  token, code, state value or email is logged.
- The agent holds no permission state (GH-161): every chat run loads the
  requesting org's tool policy (its matrix, promoted tier-2 pairs and enabled
  services) and passes it as ``tool_policy``, so one org's settings never
  reach another org's runs.
- Prompt context per run (GH-170): every chat run (a message, an approved
  confirmation) also loads the caller's ``PromptContext`` (with
  ``TenantContext.from_principal``: the org's instructions and default
  response language, the user's response language, timezone and personal
  instructions; no account identifier) and passes it as ``prompt_context``,
  so a change applies to the next message. The instructions are content:
  never logged; a failing load is the generic 500 with no run started.
- Send-path reads (GH-244): a message to a chat id reads the tool policy,
  the prompt context and the chat's owner check in one statement
  (``turn_setup.load_turn_setup``, scoped to the session's org and user; a
  chat the caller can't reach is the same 404 before the hold), then, under
  the chat's hold, the chat and its latest messages in one statement. The
  legacy ``/api/message`` and ``/api/confirm`` keep the separate loaders
  (``org_permissions.load_tool_policy``,
  ``scoped_settings.load_prompt_context``).
- Turn timings (GH-244): ``request_timing.TimingMiddleware`` (pure ASGI,
  right inside ``RequestIdMiddleware``) logs one content-free line per
  request on the three turn routes (the request ID, the route label, the
  status, counts and durations only); a streamed turn's line is written by
  its run task once the turn is stored and reported, before its title call.
- Platform defaults apply without a restart (GH-160): the chat routes read
  the stored limits through the settings cache on every request (the message
  length, each agent run's tool-call, context and confirmation timeout
  limits, GH-242, its LLM retry limit and, GH-24, the pending-confirmation
  limit),
  logins the Super Admin session policy, the login throttle its lockout
  thresholds, an org deletion its grace period and the audit retention job
  its months.
- CSRF: ``CrossOriginProtectionMiddleware`` implements Go's
  CrossOriginProtection check on every non-GET/HEAD/OPTIONS request, before
  authentication and handlers (the login included): ``Sec-Fetch-Site`` must be
  ``same-origin``/``none``; without it, an ``Origin`` must match ``Host``.
  Refusals are 403 ``{"detail": "Cross-origin request refused"}``.
- Login failures are one generic 401 for every cause (no user enumeration);
  the email, password and session token are never logged or echoed.
- Brute-force protection (GH-157, ``admino.login_throttle``): failed logins
  are counted per account and per client IP in PostgreSQL. From the third
  failure in the window (15 minutes by default) an attempt waits (1, 2, 4,
  then 8 seconds) before its check; the 10th (by default) locks the account
  or IP for 15 minutes (by default; audited as ``login.lockout``). The
  window, the threshold and the lock duration are the stored platform
  security settings (GH-160). A locked login is the same 401 as a wrong
  password. The password reset confirm and the two invitation link routes
  share the login's per-IP counter: a locked IP gets 429 "Too many
  attempts. Try again later." before any lookup, an unusable link counts as
  a failure, and a usable one (a password-policy 422 included) releases its
  reservation. A reset request
  from a locked IP gets the same 429 before anything is queued; otherwise it
  waits out the IP's delay and never counts. The throttle runs after the
  route's token bucket and after body validation.
- A password reset request answers the same empty 202 for every email, before
  any account work: the service runs as a background task after the response,
  so neither the body nor the timing tells whether the account exists. Reset
  links are built from ``server.public_url`` only, never from the request's
  Host or X-Forwarded-* headers. A failed confirm is one generic 400 for every
  link that can't be used; the email, token, link and password are never
  logged or echoed.
- Rate limits are per caller: one token bucket per (route, ``user:<id>``) on
  session routes and per (route, ``ip:<host>``) on public routes (the health
  check, the login, the password reset and the invitation link routes), so
  one caller can't throttle another. Idle buckets are evicted and the map is
  capped (LRU).
  The buckets live in process memory; the lockouts above live in PostgreSQL
  and survive a restart.
  Cookies that resolve to no session spend a per-IP budget, so a stream of
  random cookies is refused (429) before it costs database lookups.
- No raw user content, assistant text, or tool args logged at INFO or below.
- Error responses use generic messages; never leak internal paths or config.
- ``SecurityHeadersMiddleware`` is pure ASGI (GH-8): it sets the headers on
  the response start and passes ``receive`` and every body message through,
  so a stream reaches the client frame by frame and its disconnect reaches
  the route.
- Request IDs and unhandled errors (GH-158): ``RequestIdMiddleware`` (pure
  ASGI, outermost) gives every HTTP request a fresh ``uuid4().hex`` in
  ``logs.request_id_var``, so every log line of the request carries it, and
  sends it back as ``X-Request-ID`` on every response (the CSRF 403, 404,
  422, 429, 500 and static files included). An incoming ``X-Request-ID`` is
  ignored. An exception escaping the app is logged once as ``"Unhandled
  exception: <ClassName>"`` (no exc_info, no message, so no traceback) and
  answered 500 ``{"detail": "Internal error"}``; it is never re-raised.
- Health exposure (GH-158): the public ``/health`` answers the database
  status only (per-IP bucket, before the database check) and never probes
  the LLM. The provider, model and reachability are behind
  ``Capability.PLATFORM_DIAGNOSTICS_VIEW`` (Super Admin) on
  ``/api/platform/diagnostics``, which spends a per-user bucket and checks the
  capability before any probe.
- CORS allows only ``server.public_url`` as an origin; no credentials, and
  only ``Content-Type`` as an allowed request header. ``/openapi.json``,
  Swagger UI and ReDoc are disabled.
- HSTS is not set by the app: the Caddy proxy of the production profile
  (docker-compose.prod.yml) terminates TLS and sends it.
- X-Forwarded-For/Proto are believed only from a peer inside
  ``server.trusted_proxies`` (empty by default: no peer, loopback included);
  the resolved client address feeds the per-IP rate limits and the audit
  events. X-Forwarded-Host is never trusted.
- Does NOT import check_permission — permission decisions live in agent/registry.
- Imports only the ``PROMOTABLE_DENIALS`` constant from permissions.py.

Deployment note:
- Chats and their messages live in PostgreSQL. In-memory state: the bounded
  ``_chat_runtime`` (``admino.chat_runtime.ChatRuntime``: per-chat run
  locks, streamed runs' stop signals (GH-8) and pending confirmations, at
  most ``_MAX_CHAT_RUNTIME_ENTRIES`` entries and
  ``_MAX_CHAT_RUNTIME_ENTRIES_PER_USER`` per user, idle ones evicted
  after ``_CHAT_IDLE_EVICT_S``; GH-24: only the two message routes create
  entries (a confirm on a chat without one is the 404 "No pending
  confirmation for this session"); a user at their bound loses their own
  least recently used entry that only holds a lock, else gets the 429
  ``rate_limit`` before any run; at capacity the requester's own lock-only
  entry goes first, then anyone's, then the requester's own pending
  confirmation, never another user's; 503 ``chats_busy`` when nothing can
  go; cleared by ``create_app``, so a restart turns a pending confirmation
  into ``expired``), ``_rate_buckets``, ``_oauth_pending_states`` and
  the detached streamed runs (``event_stream.detach``) and the attachment
  processing queue (``_processing``, GH-187: replaced by ``create_app``; files
  a restart left unprocessed are queued again at startup);
  ``admino.org_permissions`` keeps the pending promotions in memory (as
  ``admino.oauth`` does the access-token cache).
  This requires a **single-worker** ASGI deployment. Running multiple
  workers (e.g. uvicorn --workers 2) will silently split state across
  processes. Use ``--workers 1`` (the default).

Legacy chat session ID note (until #177):
- The legacy routes take a client-provided session id, validated by
  Pydantic (alphanumeric, hyphens, underscores, max 64 chars). It names the
  caller's own persisted chat (``chats.legacy_session_id``, unique per live
  chat of an owner), so a user reusing another user's session id gets a chat
  of their own and can neither read, confirm nor cancel the other user's.
- A new session id's chat is created only once its run can start (GH-266):
  it gets a server-generated id whose runtime entry is held first, so a 429
  ``rate_limit`` or 503 ``chats_busy`` leaves no chat behind.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import os
import re
import secrets
import stat
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path as PathLib
from typing import TYPE_CHECKING, Annotated, Final, Literal, NamedTuple, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4  # UUID at runtime: FastAPI resolves path parameter annotations

import httpx
from fastapi import (
    BackgroundTasks,
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError
from starlette.background import BackgroundTask
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect
from starlette.staticfiles import StaticFiles

from admino import (
    accounts,
    attachment_gc,
    attachment_processing,
    attachment_types,
    attachments,
    auth,
    chat_titles,
    chats,
    event_stream,
    invitations,
    llm_policy,
    login_throttle,
    my_account,
    org_permissions,
    org_users,
    organizations,
    password_reset,
    passwords,
    platform_users,
    request_timing,
    scoped_settings,
    session_management,
    sessions,
    turn_setup,
    untrusted,
)
from admino.access import Capability, Principal, can
from admino.attachment_types import AttachmentRefusedError
from admino.chat_runtime import (
    ChatRunActiveError,
    ChatRuntime,
    ChatRuntimeFullError,
    ChatRuntimeUserLimitError,
    PendingConfirmationLimitError,
)
from admino.event_stream import EventStreamResponse
from admino.logs import request_id_var, safe_log
from admino.models import (
    PROVIDER_TOOLS,
    AgentConfig,
    AgentResult,
    AttachmentSummary,
    ChatContext,
    ChatCreateRequest,
    ChatDetailResponse,
    ChatListResponse,
    ChatMessageCreate,
    ChatMessageView,
    ChatRequest,
    ChatResponse,
    ChatStopResponse,
    ChatSummary,
    ChatUpdateRequest,
    ConfirmRequest,
    CriticalPermissionPromote,
    CriticalPermissionsResponse,
    CriticalPermissionState,
    DeltaPayload,
    DonePayload,
    ErrorPayload,
    InvitationAcceptRequest,
    InvitationCreateRequest,
    InvitationDetails,
    InvitationListResponse,
    InvitationSummary,
    LLMMessage,
    LoginRequest,
    MeResponse,
    MessageSavedPayload,
    MyAccountPatch,
    MyAccountResponse,
    OAuthAuthorizeResponse,
    OAuthConnectionStatus,
    OAuthServiceStatus,
    OrgCreateRequest,
    OrgCreateResponse,
    OrgLimitsPatch,
    OrgListResponse,
    OrgMetadata,
    OrgResidencyPatch,
    OrgSettingsPatch,
    OrgSettingsResponse,
    OrgSummary,
    OrgUserListResponse,
    OrgUserPatch,
    OrgUserSummary,
    PasswordChangeRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PendingConfirmation,
    PendingConfirmationSummary,
    PermissionPatch,
    PermissionsResponse,
    PermissionsSummaryResponse,
    PlatformDiagnosticsResponse,
    PlatformReinviteRequest,
    PlatformSettingsPatch,
    PlatformSettingsResponse,
    PlatformUserListResponse,
    PlatformUserSummary,
    RunStartedPayload,
    SessionListResponse,
    SettingsLLM,
    SSEEvent,
    TitlePayload,
    UserSettingsPatch,
    UserSettingsResponse,
)
from admino.oauth import (
    OAuthError,
    OAuthProvider,
    OAuthToken,
    access_tokens,
    build_google_consent_url,
    build_microsoft_consent_url,
    encrypt_refresh_token,
    exchange_google_code,
    exchange_microsoft_code,
    get_connection_status,
    get_google_user_email,
    revoke_and_delete_token,
    save_token,
)
from admino.permissions import PROMOTABLE_DENIALS
from admino.proxy_headers import TrustedProxyHeadersMiddleware
from admino.streaming import DisplayDeltas, RunStream, display_pieces
from admino.tenancy import TenantContext

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Sequence

    import asyncpg
    from pydantic import BaseModel
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from admino.agent import Agent
    from admino.attachment_types import RefusalReason
    from admino.config import AppConfig
    from admino.llm import LLMClient
    from admino.models import (
        AgentStatus,
        LLMErrorCode,
        MessageStatus,
        SettingsPatchLLM,
        ToolCallRecord,
        ToolPolicy,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

# Sent on every response: by SecurityHeadersMiddleware, and by
# RequestIdMiddleware on the 500 it answers for an unhandled exception.
_SECURITY_HEADERS: Final[dict[str, str]] = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


class SecurityHeadersMiddleware:
    """Injects security response headers on every HTTP response.

    Mitigates XSS (CSP), clickjacking (X-Frame-Options), MIME-sniffing
    (X-Content-Type-Options), and information leakage (Referrer-Policy,
    Permissions-Policy). Applied even for local-only deployments because
    the PWA runs in a browser that respects these headers.

    A pure ASGI middleware (GH-8): it sets the headers on the response start
    and passes ``receive`` and every body message through untouched, so a
    streamed chat reply reaches the client frame by frame and its client's
    disconnect reaches the route.

    Note: ``Strict-Transport-Security`` (HSTS) is intentionally omitted: the
    app itself serves plain HTTP, and TLS terminates at the reverse proxy. The
    production profile's Caddy proxy (docker-compose.prod.yml) sends HSTS.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request on, adding the security headers to its response (replacing any)."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(_SECURITY_HEADERS)
            await send(message)

        await self._app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
# CSRF: cross-origin protection
# ---------------------------------------------------------------------------

# Methods that never change state: exempt from the cross-origin check.
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
# Sec-Fetch-Site values a browser sends for a same-origin or user-initiated request.
_SAME_ORIGIN_FETCH_SITES: Final = frozenset({"same-origin", "none"})
_CSRF_REFUSED_DETAIL: Final = "Cross-origin request refused"


def _is_cross_origin_request(method: str, headers: Headers) -> bool:
    """Return True when a request must be refused as cross-origin (CSRF).

    Go 1.25 ``CrossOriginProtection`` algorithm:
    1. GET, HEAD and OPTIONS are safe by method and always pass.
    2. If ``Sec-Fetch-Site`` is present, only ``same-origin`` and ``none``
       (a user-initiated navigation) pass; any other value is refused.
    3. Otherwise, if ``Origin`` is present, it passes only when its
       host[:port] equals the ``Host`` header (the scheme is ignored: TLS
       terminates at the proxy). ``Origin: null`` or a malformed origin is refused.
    4. With neither header the request doesn't come from a browser and passes;
       the SameSite=Strict session cookie covers older browsers.

    Args:
        method: The HTTP request method.
        headers: The request headers.

    Returns:
        True if the request is cross-origin and must be refused.
    """
    if method.upper() in _SAFE_METHODS:
        return False
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site.strip().lower() not in _SAME_ORIGIN_FETCH_SITES
    origin = headers.get("origin")
    if origin is None:
        return False
    try:
        origin_host = urlsplit(origin.strip()).netloc
    except ValueError:
        return True
    host = headers.get("host", "")
    return not origin_host or origin_host.lower() != host.strip().lower()


class CrossOriginProtectionMiddleware:
    """Refuses cross-origin state-changing requests before routing (CSRF defence).

    A pure ASGI middleware, so the refusal happens before authentication,
    rate limiting and handlers run, the login included (login CSRF). A refused
    request gets 403 ``{"detail": "Cross-origin request refused"}``; nothing
    from the request is echoed or logged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request on, or answer 403 when it is cross-origin."""
        if scope["type"] == "http" and _is_cross_origin_request(
            scope["method"], Headers(scope=scope)
        ):
            response = JSONResponse(status_code=403, content={"detail": _CSRF_REFUSED_DETAIL})
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


# ---------------------------------------------------------------------------
# Request IDs and unhandled exceptions
# ---------------------------------------------------------------------------

_INTERNAL_ERROR_DETAIL: Final = "Internal error"


class RequestIdMiddleware:
    """Gives every HTTP request an ID and turns an escaping exception into a generic 500.

    A pure ASGI middleware, installed outermost. Each request gets a fresh
    ``uuid4().hex``, held in ``logs.request_id_var`` while the request runs
    (every log line of the request carries it) and sent back as
    ``X-Request-ID`` on every response. An incoming ``X-Request-ID`` is
    ignored: never echoed, logged or used.

    An exception that escapes the app is logged once at ERROR as
    ``"Unhandled exception: <ClassName>"`` (no exc_info, no message) and
    answered 500 ``{"detail": "Internal error"}`` (with the security headers,
    since SecurityHeadersMiddleware sits inside and never sees it) when the
    response hasn't started. It is never re-raised, so neither Starlette nor uvicorn logs a
    traceback. HTTPExceptions are answered inside the app and never get here.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the request with its ID; answer 500 for an unhandled exception."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request_id = uuid4().hex
        header = (b"x-request-id", request_id.encode("ascii"))
        started = False

        async def send_with_request_id(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message.get("headers", []), header]}
            await send(message)

        token = request_id_var.set(request_id)
        try:
            await self._app(scope, receive, send_with_request_id)
        except Exception as exc:
            logger.error("Unhandled exception: %s", type(exc).__name__)
            if not started:
                response = JSONResponse(
                    status_code=500,
                    content={"detail": _INTERNAL_ERROR_DETAIL},
                    headers=_SECURITY_HEADERS,
                )
                await response(scope, receive, send_with_request_id)
        finally:
            request_id_var.reset(token)


# ---------------------------------------------------------------------------
# PWA static files with the client-route fallback
# ---------------------------------------------------------------------------

# First path segments that belong to the server, never to the PWA's router.
_SERVER_PATH_PREFIXES: Final[frozenset[str]] = frozenset({"api", "health"})


def _is_client_route(path: str) -> bool:
    """Whether a static-files ``path`` names a PWA client route.

    ``path`` is the relative, normalized path StaticFiles resolves (OS
    separators, ``"."`` for the root). A client route is outside ``api`` and
    ``health`` and its last segment has no file extension (no ``"."``).
    """
    segments = [s for s in path.replace(os.sep, "/").split("/") if s not in ("", ".")]
    return not segments or (segments[0] not in _SERVER_PATH_PREFIXES and "." not in segments[-1])


# Vite's output naming for bundled files (static-src/vite.config.ts: assetFileNames,
# chunkFileNames, entryFileNames): ``assets/<name>-<8-char content hash>.<ext>``, matched
# in full against the relative, "/"-separated path. Such a file never changes under its
# name: a new build writes a new name.
_HASHED_ASSET_PATH: Final = re.compile(r"assets/[^/]+-[A-Za-z0-9_-]{8}\.[A-Za-z0-9]+")
_IMMUTABLE_CACHE: Final = "public, max-age=31536000, immutable"
# Every other file keeps its name across releases (index.html, the service worker and
# its registration, the manifest, workbox-*.js, fonts, icons): it changes in place, so a
# browser must revalidate it on every use. StaticFiles' ETag / Last-Modified keep that
# cheap: an unchanged file is a bodiless 304.
_REVALIDATE_CACHE: Final = "no-cache"


def _cache_control(path: str, status_code: int) -> str:
    """The ``Cache-Control`` of the static mount's ``status_code`` response for ``path``.

    ``path`` is the relative, normalized path StaticFiles resolves (OS
    separators). Only a found hashed asset (200, or the 304 of a matching
    ``If-None-Match``) is immutable; a missing one never is.
    """
    hashed = _HASHED_ASSET_PATH.fullmatch(path.replace(os.sep, "/")) is not None
    return _IMMUTABLE_CACHE if hashed and status_code in (200, 304) else _REVALIDATE_CACHE


class _SpaStaticFiles(StaticFiles):
    """StaticFiles that answer a missing client route with ``index.html``.

    The PWA routes on the client (history mode), so a first visit to an
    emailed ``/reset-password#token=...`` link or a reload of ``/login`` must
    get ``index.html`` rather than a 404.

    Caching (GH-244): a hashed asset (``_HASHED_ASSET_PATH``) is cached for a
    year as immutable; every other response of the mount (``index.html``, the
    client-route fallback, the service worker, the manifest, fonts, icons, a
    404 of a ``404.html``) gets ``no-cache``. A 404 raised for a missing file
    is answered by the app's exception handler, without either.

    Security notes:
    - The fallback file is resolved by StaticFiles itself (fixed name
      ``index.html``), so no filesystem path is built from the request and
      StaticFiles' traversal guard still applies to every lookup.
    - ``api``/``health`` paths and missing files with an extension keep their
      404; other methods keep StaticFiles' 405. Nothing from the request is
      echoed or logged.
    - A ``404.html`` in the directory (which html mode returns with status 404
      instead of raising) doesn't defeat the fallback.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        """Serve ``path`` (``index.html`` for a missing client route) with its Cache-Control."""
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or not _is_client_route(path):
                raise
            response = await super().get_response("index.html", scope)
        else:
            if response.status_code == 404 and _is_client_route(path):
                response = await super().get_response("index.html", scope)
        # A client route has no extension, so its fallback never matches the hashed pattern.
        response.headers["Cache-Control"] = _cache_control(path, response.status_code)
        return response


# ---------------------------------------------------------------------------
# Rate limiter (per route and caller)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple in-process token-bucket rate limiter for one (route, caller).

    Limits requests per second to prevent resource exhaustion (LLM inference,
    memory, Argon2 CPU). Not shared across workers — requires single-worker
    deployment (already required by the in-memory chat runtime).

    Args:
        rate: Tokens added per second.
        capacity: Maximum burst capacity.
        now: The current ``time.monotonic()`` value.
    """

    __slots__ = ("_capacity", "_rate", "_tokens", "last_used")

    def __init__(self, rate: float, capacity: int, now: float) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = float(capacity)
        self.last_used = now

    def _refill(self, now: float) -> None:
        """Add the tokens earned since the last use, up to the burst capacity."""
        elapsed = max(0.0, now - self.last_used)
        self._tokens = min(float(self._capacity), self._tokens + elapsed * self._rate)
        self.last_used = now

    def allow(self, now: float) -> bool:
        """Refill for the time elapsed, then consume one token if there is one."""
        self._refill(now)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def has_token(self, now: float) -> bool:
        """Refill for the time elapsed and report whether a token is left, consuming none."""
        self._refill(now)
        return self._tokens >= 1.0


# Per-route (tokens per second, burst). Route keys are stable strings, not
# URL paths with parameters. Read when a bucket is created.
_RATE_LIMITS: dict[str, tuple[float, int]] = {
    "/api/message": (0.5, 5),
    "/api/confirm": (0.5, 5),
    # GH-176: persisted chats, per user. A chat turn spends "/api/message"
    # (one LLM bucket per user, shared with the legacy route).
    "/api/chats/create": (0.5, 5),
    "/api/chats/list": (1.0, 10),
    "/api/chats/get": (1.0, 10),
    "/api/chats/patch": (0.5, 5),
    "/api/chats/delete": (0.5, 5),
    # GH-8: stopping a chat's streamed run, per user.
    "/api/chats/stop": (1.0, 10),
    # GH-187: chat attachments, per user. The upload refills one token every 2
    # seconds. Its burst below (10) is never used: the bucket's burst is the
    # platform max_files_per_message, passed when the caller's bucket is created.
    "/api/chats/attachments/create": (0.5, 10),
    "/api/attachments/get": (5.0, 50),
    "/api/attachments/content/get": (2.0, 30),
    # GH-159: the settings scopes, per user.
    "/api/me/settings/get": (1.0, 10),
    "/api/me/settings/patch": (0.5, 5),
    "/api/me/settings/reset": (0.2, 3),
    "/api/org/settings/get": (1.0, 10),
    "/api/org/settings/patch": (0.5, 5),
    "/api/platform/settings/get": (1.0, 10),
    "/api/platform/settings/patch": (0.2, 5),
    # GH-161: the org's permission matrix and critical permissions (Org Admin),
    # and the members' read-only summary, per user.
    "/api/org/permissions/get": (1.0, 5),
    "/api/org/permissions/patch": (0.2, 2),
    "/api/org/critical-permissions/get": (1.0, 5),
    "/api/org/critical-permissions/promote": (5 / 60, 5),
    "/api/org/critical-permissions/cancel": (0.5, 5),
    "/api/permissions/summary/get": (1.0, 10),
    "/api/oauth/google/authorize": (0.2, 2),
    "/api/oauth/microsoft/authorize": (0.2, 2),
    "/api/oauth/callback": (0.2, 2),
    "/api/oauth/google/status": (1.0, 5),
    "/api/oauth/microsoft/status": (1.0, 5),
    "/api/oauth/google/disconnect": (0.2, 2),
    "/api/oauth/microsoft/disconnect": (0.2, 2),
    "/api/auth/login": (0.2, 5),
    # One reset email per minute per IP after a burst of 3 (limits inbox flooding).
    "/api/auth/password-reset": (1 / 60, 3),
    "/api/auth/password-reset/confirm": (0.2, 5),
    "/api/auth/logout": (0.5, 5),
    "/api/auth/me": (1.0, 10),
    # Cookies that resolve to no session, per client IP (see require_session).
    "/api/auth/session": (1.0, 20),
    # Session management (GH-152), per user.
    "/api/me/sessions/get": (1.0, 10),
    "/api/me/sessions/delete": (0.5, 5),
    # Account self-service (GH-166), per user. A password change costs a
    # re-authentication and an Argon2 hash: a burst of 3, then one every 10 seconds.
    "/api/me/get": (1.0, 10),
    "/api/me/patch": (0.5, 5),
    "/api/me/password": (0.1, 3),
    "/api/org/users/logout": (0.5, 5),
    # Org Admin user management (GH-164), per user. Deactivating and
    # reactivating share one bucket; one reset email per minute after a burst of 3.
    "/api/org/users/get": (1.0, 10),
    "/api/org/users/patch": (0.5, 5),
    "/api/org/users/status": (0.5, 5),
    "/api/org/users/delete": (0.2, 5),
    "/api/org/users/password-reset": (1 / 60, 3),
    # Invitations (GH-153): per user on the Org Admin routes, per IP on the
    # public link routes.
    "/api/org/invitations/create": (0.2, 5),
    "/api/org/invitations/get": (1.0, 10),
    "/api/org/invitations/revoke": (0.5, 5),
    "/api/org/invitations/resend": (0.2, 5),
    "/api/auth/invitations/get": (1.0, 10),
    "/api/auth/invitations/accept": (0.2, 5),
    # Refused invitation sends (email taken, no free seat), refused email
    # changes (email taken, GH-164) and refused re-invite replacements (email
    # taken, no free seat, GH-167), per user and shared by all: a burst of 5,
    # then one a minute, so probing whether an email exists on the platform
    # stays slow.
    "/api/org/invitations/refused": (1 / 60, 5),
    # Platform organization lifecycle (GH-154), per Super Admin. Deactivating
    # and reactivating share one bucket, as do scheduling and cancelling a
    # deletion.
    "/api/platform/orgs/get": (1.0, 10),
    "/api/platform/orgs/create": (0.2, 5),
    "/api/platform/orgs/limits": (0.5, 5),
    "/api/platform/orgs/status": (0.5, 5),
    "/api/platform/orgs/deletion": (0.2, 5),
    "/api/platform/orgs/residency": (0.5, 5),
    # Super Admin user administration and org metadata (GH-167), per Super
    # Admin. Deactivating and reactivating share one bucket; one reset email
    # per minute after a burst of 3. A re-invite with an email also checks and
    # spends the refused budget above.
    "/api/platform/orgs/users/get": (1.0, 10),
    "/api/platform/orgs/metadata/get": (1.0, 10),
    "/api/platform/orgs/users/status": (0.5, 5),
    "/api/platform/orgs/users/password-reset": (1 / 60, 3),
    "/api/platform/orgs/users/invitation": (0.2, 5),
    # GH-158: the public health check, per IP. Generous: the PWA polls it every
    # 10 seconds per tab and the container healthcheck hits it too.
    "/health": (5.0, 30),
    # GH-158: platform diagnostics (the LLM probe), per Super Admin.
    "/api/platform/diagnostics": (1.0, 10),
}
# Routes without their own entry still get a bucket per caller.
_DEFAULT_RATE_LIMIT: tuple[float, int] = (1.0, 10)
# A bucket unused this long has fully refilled, so dropping it loses nothing.
_BUCKET_IDLE_TTL_S: float = 900.0
# Upper bound on the bucket map (least-recently-used buckets are dropped first).
_MAX_RATE_BUCKETS: int = 10_000

# (route, caller) -> bucket, in least-recently-used order. The caller is
# "user:<user_id>" on session routes and "ip:<client host>" on public routes
# and for failed session resolutions.
_rate_buckets: OrderedDict[tuple[str, str], _TokenBucket] = OrderedDict()
# The route key of the per-IP budget for cookies that resolve to no session.
_SESSION_FAILURE_ROUTE: Final = "/api/auth/session"
# The route key of the per-user budget for refused invitation sends, refused
# email changes and refused re-invite replacements (one "does this email exist"
# budget).
_INVITE_REFUSED_ROUTE: Final = "/api/org/invitations/refused"


def _evict_idle_buckets(now: float) -> None:
    """Drop buckets unused for at least ``_BUCKET_IDLE_TTL_S`` seconds.

    ``_rate_buckets`` is kept in least-recently-used order, so the idle
    buckets are at the front.
    """
    while _rate_buckets:
        oldest_key = next(iter(_rate_buckets))
        if now - _rate_buckets[oldest_key].last_used < _BUCKET_IDLE_TTL_S:
            return
        del _rate_buckets[oldest_key]


def _check_rate_limit(route: str, caller: str, *, burst: int | None = None) -> None:
    """Consume one token from ``caller``'s bucket for ``route``; 429 when empty.

    Each (route, caller) pair has its own bucket, so one user (or IP)
    exhausting a route never throttles another. Routes without an entry in
    ``_RATE_LIMITS`` use ``_DEFAULT_RATE_LIMIT``. Idle buckets are evicted
    and the map never exceeds ``_MAX_RATE_BUCKETS`` entries.

    Args:
        route: The route key (e.g. ``"/api/message"``).
        caller: ``"user:<user_id>"`` or ``"ip:<client host>"``.
        burst: The burst of a bucket created now, instead of the route's own
            (GH-187: the upload's is a platform setting).

    Raises:
        HTTPException: 429 if the caller's bucket is empty.
    """
    now = time.monotonic()
    if not _bucket_for(route, caller, now, burst=burst).allow(now):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _bucket_for(route: str, caller: str, now: float, *, burst: int | None = None) -> _TokenBucket:
    """Return (creating it if needed) the bucket of ``(route, caller)``, marked most recent.

    A bucket created now gets ``burst`` when given, else the route's own.
    Evicts idle buckets first, and keeps the map within ``_MAX_RATE_BUCKETS``.
    """
    _evict_idle_buckets(now)
    key = (route, caller)
    bucket = _rate_buckets.get(key)
    if bucket is None:
        rate, route_burst = _RATE_LIMITS.get(route, _DEFAULT_RATE_LIMIT)
        while _rate_buckets and len(_rate_buckets) >= _MAX_RATE_BUCKETS:
            _rate_buckets.popitem(last=False)
        bucket = _TokenBucket(rate, route_burst if burst is None else burst, now)
        _rate_buckets[key] = bucket
    else:
        _rate_buckets.move_to_end(key)
    return bucket


def _budget_exhausted(route: str, caller: str) -> bool:
    """True when ``caller`` has spent its budget of failures on ``route``.

    Only reads the bucket: a caller that never fails never gets one. Used for
    cookies that resolve to no session, and for refused invitation sends and
    email changes.
    """
    bucket = _rate_buckets.get((route, caller))
    return bucket is not None and not bucket.has_token(time.monotonic())


def _spend_budget(route: str, caller: str) -> None:
    """Spend one token of ``caller``'s failure budget on ``route``."""
    now = time.monotonic()
    _bucket_for(route, caller, now).allow(now)


def _user_caller(principal: Principal) -> str:
    """The rate-limit caller key of a logged-in principal."""
    return f"user:{principal.user_id}"


def _client_ip(request: Request) -> str:
    """The client address of the request (``"unknown"`` when the server has none).

    The peer address, or the resolved client address when the request came
    through a trusted proxy (``server.trusted_proxies``).
    """
    return request.client.host if request.client is not None else "unknown"


# ---------------------------------------------------------------------------
# Module-level state — set during create_app()
# ---------------------------------------------------------------------------

# Chats and their messages are persisted (GH-176, admino.chats). What stays in
# memory is one bounded ChatRuntime: per-chat run locks (two runs of one chat
# never overlap, so the second loads what the first stored) and the chat's
# pending confirmation (one at a time; lost on a restart, then shown as
# expired). Routes read this module global at request time (tests swap it).
_MAX_CHAT_RUNTIME_ENTRIES: Final = 1024
# One user holds at most this many entries (GH-24), so one user or org can't fill
# the runtime and push everyone else's locks and confirmations out.
_MAX_CHAT_RUNTIME_ENTRIES_PER_USER: Final = 16
# An entry unused this long, not in use and without a pending confirmation,
# is evicted when another one is created.
_CHAT_IDLE_EVICT_S: Final = 900.0
_chat_runtime = ChatRuntime(
    max_entries=_MAX_CHAT_RUNTIME_ENTRIES,
    idle_s=_CHAT_IDLE_EVICT_S,
    max_entries_per_user=_MAX_CHAT_RUNTIME_ENTRIES_PER_USER,
)
# The background reaper's pause between two passes (GH-24): an expired confirmation
# is gone within this long even when no chat request comes in.
_CONFIRMATION_REAP_INTERVAL_S: Final = 30.0
# How long the shutdown waits for the detached streamed runs it asked to stop (GH-8):
# one tool call's time plus the store. The container's stop grace period must be
# longer, or the process is killed first. Read by the lifespan at shutdown.
_DRAIN_TIMEOUT_S: Final = 30.0
# GH-187: the bounded pool that processes stored attachments after their upload's 201.
# Replaced by create_app (a restart's state); the upload route and the lifespan read
# this module global at call time (tests swap it).
_processing = attachment_processing.ProcessingPool()

# OAuth state binding (GH-162): the authorize route stores the state with the
# initiating user and session, and sets this short-lived cookie (HttpOnly,
# SameSite=Lax, scoped to the callback path) to the same value. The callback
# requires both, so only the browser that started the authorization can
# complete it, and only for the user who started it.
OAUTH_STATE_COOKIE_NAME: Final = "admino_oauth_state"
_OAUTH_CALLBACK_PATH: Final = "/api/oauth/callback"
# The 403 explanation of the authorize route in a data residency org.
OAUTH_RESIDENCY_DETAIL: Final = (
    "Your organization's data residency policy doesn't allow Google or Microsoft accounts."
)


class OAuthPendingState(NamedTuple):
    """An authorization waiting for its callback: what the state is bound to (GH-162)."""

    created_at: float  # time.time() at authorize
    provider: OAuthProvider
    redirect_uri: str
    user_id: UUID  # the initiating user
    session_id: UUID  # the initiating session (AuthenticatedSession.session_id)


# OAuth CSRF state tokens: maps state string -> its OAuthPendingState. Entries
# expire after _OAUTH_STATE_TTL_S seconds (also the binding cookie's Max-Age)
# and are reaped on each authorize call. A user has at most one entry (a new
# authorize replaces their earlier one), so the map is bounded by the users
# who started a connection in the last 10 minutes, and no user's authorize
# ever evicts another user's (or org's) pending state.
_OAUTH_STATE_TTL_S: int = 600  # 10 minutes
_oauth_pending_states: dict[str, OAuthPendingState] = {}

# Injected at app creation time by create_app().
_agent: Agent | None = None
_config: AppConfig | None = None


# ---------------------------------------------------------------------------
# Chat helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    """The current aware UTC time: the only clock of the confirmation expiry (GH-24).

    Read by ``_reap_expired_confirmations`` and by ``post_confirm``'s expiry
    check, so both agree on when a confirmation expired (tests move it).
    """
    return datetime.now(UTC)


def _reap_expired_confirmations() -> None:
    """Drop every expired pending confirmation from ``_chat_runtime``.

    Called unconditionally at the top of the chat turns, ``post_confirm`` and
    the chat detail (before taking a chat's lock), and every
    ``_CONFIRMATION_REAP_INTERVAL_S`` by ``_run_confirmation_reaper``, so
    stale confirmations never accumulate, an expired one frees its slot of
    the per-user pending limit and a chat shows it as ``expired``. This is
    the enforcement point for the stored ``confirmation_timeout_s``
    (``now >= expires_at`` by ``_utc_now``).

    IMPORTANT: This function must remain synchronous (no ``await`` calls).
    Callers invoke it outside per-chat locks, so it must complete
    atomically within a single event-loop tick to avoid cross-chat
    race conditions on the runtime's pending confirmations. It never
    waits for a chat's lock and never touches the database.
    """
    reaped = _chat_runtime.reap_expired(_utc_now())
    if reaped:
        logger.info("Reaped %d expired confirmation(s)", reaped)


async def _run_confirmation_reaper() -> None:
    """Reap expired confirmations every ``_CONFIRMATION_REAP_INTERVAL_S``, until cancelled.

    The background half of the expiry (GH-24): a confirmation expires even
    when no chat request comes in. Each pass is ``_reap_expired_confirmations``
    (memory only: no chat lock, no query), so it never blocks a request. A
    failing pass is logged by its exception class only (never its message)
    and the loop goes on. The interval and ``asyncio.sleep`` are looked up on
    every pass.
    """
    while True:
        await asyncio.sleep(_CONFIRMATION_REAP_INTERVAL_S)
        try:
            _reap_expired_confirmations()
        except Exception as exc:
            # A broken pass must not end the expiry for the life of the process.
            logger.warning("Confirmation reaper pass failed: %s", type(exc).__name__)


_CANCELLED_TOOL_RESULT_MSG = "Tool call cancelled — user sent a new message instead of confirming."
# The stored tool result answering a denied call (GH-176), so the history stays well-formed.
_DENIED_TOOL_RESULT_MSG: Final = "Tool call denied by the user."
# The stored tool result answering a call whose confirmation the per-user pending limit
# refused (GH-24).
_PENDING_LIMIT_TOOL_RESULT_MSG: Final = "Tool call denied: too many confirmations are pending."
_NO_PENDING_DETAIL: Final = "No pending confirmation for this session"

# The documented error bodies of the chat routes (GH-176).
_CHAT_NOT_FOUND_BODY: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_INVALID_CURSOR_BODY: Final = {"detail": "Invalid cursor", "reason": "invalid_cursor"}
_CHATS_BUSY_BODY: Final = {
    "detail": "Too many active chats. Try again shortly.",
    "reason": "chats_busy",
}
# GH-24: the caller is at their per-user chat-runtime bound.
_USER_CHATS_BUSY_BODY: Final = {
    "detail": "Too many of your chats are active. Try again shortly.",
    "reason": "rate_limit",
}
# GH-8: a message to a chat whose run is going (never queued behind it).
_RUN_ACTIVE_BODY: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
# GH-187: the documented error bodies of the attachment routes and of a message's files.
_ATTACHMENT_NOT_FOUND_BODY: Final = {
    "detail": "Attachment not found",
    "reason": "attachment_not_found",
}
_ATTACHMENT_ALREADY_SENT_BODY: Final = {
    "detail": "Attachment already sent",
    "reason": "attachment_already_sent",
}
_TOO_MANY_FILES_BODY: Final = {
    "detail": "Too many files for one message",
    "reason": "too_many_files",
}

# The stored status of a run's last message: a run's ``final`` is ``complete``.
_STORED_STATUS: Final[dict[AgentStatus, MessageStatus]] = {
    "final": "complete",
    "awaiting_confirmation": "awaiting_confirmation",
    "limit_reached": "limit_reached",
    "error": "error",
    "stopped": "stopped",
}
# ChatResponse.status: a JSON run passes the agent no stream, so it never ends "stopped".
_JsonStatus = Literal["final", "awaiting_confirmation", "limit_reached", "error"]


def _summarise_pending(pending: PendingConfirmation) -> PendingConfirmationSummary:
    """Project a ``PendingConfirmation`` into the API-safe summary.

    Includes sanitized tool arguments so the PWA can display call details
    in the confirmation card. Excludes the internal ``session_id``.
    Credential patterns in the arguments are stripped at every depth by the
    ``PendingConfirmationSummary`` validator.
    """
    return PendingConfirmationSummary(
        confirmation_id=pending.confirmation_id,
        tool=pending.tool_call.tool,
        action=pending.tool_call.action,
        args=pending.tool_call.args,
        expires_at=pending.expires_at,
    )


def _close_dangling_tool_use(history: list[LLMMessage]) -> list[LLMMessage]:
    """Append synthetic cancelled tool_result messages for any dangling tool_use.

    Anthropic's API rejects a conversation where an assistant message with
    ``tool_use`` blocks is not immediately followed by matching ``tool_result``
    blocks. That situation arises when the agent short-circuits on a pending
    confirmation (see ``agent.py`` returning ``awaiting_confirmation`` after
    appending the assistant turn): the stored history now ends with a
    trailing ``tool_use`` that has no companion result.

    If the user then sends a new message (instead of using
    ``/api/confirm/{id}``), the next LLM call would fail with HTTP 400. This
    helper rewrites the history so the contract holds: for each tool_use_block
    in the last assistant message without a matching ``tool`` message after
    it, append a synthetic ``tool`` message stating the call was cancelled.
    GH-176: the turn stores these synthetic results with its messages, and a
    denial reuses them (the denied call's result reworded), so the persisted
    history stays well-formed for every later load.

    Returns a new list; the input is not mutated.
    """
    if not history:
        return history

    # Walk from the end collecting trailing tool messages, until we hit
    # the most recent assistant turn. A user/system message before reaching
    # an assistant means there is nothing to close.
    trailing_tool_ids: set[str] = set()
    assistant_idx: int | None = None
    for i in range(len(history) - 1, -1, -1):
        msg = history[i]
        if msg.role == "tool":
            if msg.tool_call_id:
                trailing_tool_ids.add(msg.tool_call_id)
            continue
        if msg.role == "assistant":
            assistant_idx = i
            break
        # user or system — no dangling tool_use in play.
        return history

    if assistant_idx is None:
        return history

    assistant = history[assistant_idx]
    if not assistant.tool_use_blocks:
        return history

    dangling_ids: list[str] = []
    for block in assistant.tool_use_blocks:
        block_id = block.get("id")
        if isinstance(block_id, str) and block_id and block_id not in trailing_tool_ids:
            dangling_ids.append(block_id)

    if not dangling_ids:
        return history

    cleaned = list(history)
    for block_id in dangling_ids:
        cleaned.append(
            LLMMessage(
                role="tool",
                content=_CANCELLED_TOOL_RESULT_MSG,
                tool_call_id=block_id,
            )
        )
    return cleaned


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

_UNAUTHORIZED_DETAIL: Final = "Unauthorized"


async def require_session(request: Request) -> sessions.AuthenticatedSession:
    """FastAPI dependency: the session the ``admino_session`` cookie belongs to.

    ``sessions.resolve_session`` re-checks the session and its account in the
    database on every request (a deleted, expired or idle session, a
    deactivated user or org all resolve to nothing) and refreshes its
    ``last_seen_at`` at most once a minute. Other cookies and ``Authorization``
    headers are ignored.

    Args:
        request: The incoming request.

    Returns:
        The resolved ``AuthenticatedSession`` (with its ``Principal``).

    Per-user rate limits only engage once a session resolves, so cookies that
    resolve to no session are budgeted per client IP instead: each one spends a
    token, and an IP that has spent its budget gets 429 before any database
    lookup. A request without a cookie costs no lookup and spends nothing.

    Raises:
        HTTPException: 401 ``Unauthorized`` without a cookie or when the token
            resolves to no usable session; 429 when the client IP has spent
            its budget of unresolved cookies. The token is never logged.
    """
    from admino.database import get_pool

    token = request.cookies.get(sessions.SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED_DETAIL)
    caller = f"ip:{_client_ip(request)}"
    if _budget_exhausted(_SESSION_FAILURE_ROUTE, caller):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    session = await sessions.resolve_session(get_pool(), token)
    if session is None:
        _spend_budget(_SESSION_FAILURE_ROUTE, caller)
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED_DETAIL)
    return session


# The resolved session of the caller (401 without one).
_SessionDep = Annotated[sessions.AuthenticatedSession, Depends(require_session)]


async def require_principal(session: _SessionDep) -> Principal:
    """FastAPI dependency: the logged-in ``Principal`` (401 without a session)."""
    return session.principal


# The logged-in principal (401 without a session).
_PrincipalDep = Annotated[Principal, Depends(require_principal)]


async def require_chat_sender(principal: _PrincipalDep) -> Principal:
    """FastAPI dependency: a logged-in principal allowed to chat.

    Raises:
        HTTPException: 403 ``Forbidden`` unless the principal has
            ``Capability.CHAT_SEND`` (a Viewer or a Super Admin has not).
    """
    if not can(principal, Capability.CHAT_SEND):
        raise HTTPException(status_code=403, detail="Forbidden")
    return principal


# A logged-in principal with chat.send (401 without a session, 403 without the role).
_ChatSenderDep = Annotated[Principal, Depends(require_chat_sender)]


async def require_file_uploader(principal: _PrincipalDep) -> Principal:
    """FastAPI dependency: a logged-in principal allowed to upload files (GH-187).

    Raises:
        HTTPException: 403 ``Forbidden`` unless the principal has
            ``Capability.FILE_UPLOAD`` (a Viewer or a Super Admin has not).
    """
    if not can(principal, Capability.FILE_UPLOAD):
        raise HTTPException(status_code=403, detail="Forbidden")
    return principal


# A logged-in principal with file.upload (401 without a session, 403 without the role).
_FileUploaderDep = Annotated[Principal, Depends(require_file_uploader)]


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------


def _format_sse(event: SSEEvent) -> str:
    """Format an SSEEvent model into a wire-format SSE frame.

    Args:
        event: Validated SSE event with event type and JSON data.

    Returns:
        A string in SSE wire format: ``event: <type>\\ndata: <data>\\n\\n``.
    """
    return f"event: {event.event}\ndata: {event.data}\n\n"


def _make_sse_event(event_type: str, payload: dict[str, object]) -> str:
    """Create and format an SSE frame from an event type and payload dict.

    The data is one line of JSON: ``json.dumps`` escapes every control and
    non-ASCII character (CR, LF, U+2028 included), so no payload value can end
    the frame or forge another one. A non-finite number is refused rather than
    written as a ``NaN``/``Infinity`` literal that isn't JSON (GH-8: the
    streamed payloads come from ``model_dump(mode="json")``, which writes null).

    Args:
        event_type: The SSE event name (e.g. 'delta', 'message_saved', 'done').
        payload: JSON-serializable dict for the data field.

    Returns:
        Wire-format SSE string.

    Raises:
        ValidationError: The event name could inject a field or a frame.
        ValueError: The payload holds a non-finite number.
    """
    sse = SSEEvent(event=event_type, data=json.dumps(payload, default=str, allow_nan=False))
    return _format_sse(sse)


# ---------------------------------------------------------------------------
# LLM (vLLM) endpoint probes
# ---------------------------------------------------------------------------


async def _get_vllm_available_models() -> list[str]:
    """Probe the local vLLM endpoint for its served model IDs.

    Only runs when the active provider is ``vllm``. Issues a short-timeout
    ``GET {vllm_base_url}/models`` and returns the list of model ``id`` strings.
    On ANY exception (unreachable, still loading, malformed payload) or a
    non-vllm provider, returns an empty list. Never raises, never logs response
    bodies.

    Returns:
        The served model IDs, or ``[]`` when the probe fails or vllm is inactive.
    """
    if _config is None or _config.llm.provider != "vllm":
        return []

    from admino.llm import strip_control_chars

    base_url = _config.llm.vllm_base_url.rstrip("/")
    url = f"{base_url}/models"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=2.0),
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            payload = resp.json()
    except (httpx.HTTPError, ValueError, TypeError):
        # Unreachable, still loading, non-2xx, or non-JSON body — degrade to [].
        return []

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return []
    models: list[str] = []
    for entry in data:
        if isinstance(entry, dict):
            model_id = entry.get("id")
            if isinstance(model_id, str) and model_id:
                models.append(strip_control_chars(model_id)[:200])
    return models


async def _get_infomaniak_available_models(provider: str) -> list[str]:
    """List the models offered by the live Infomaniak client's product.

    Only runs when ``provider`` (the stored platform provider) is
    ``infomaniak`` AND the agent's live LLM client is an ``InfomaniakClient``
    (imported lazily, so no other provider loads it). Otherwise returns ``[]``.
    ``InfomaniakClient.list_models()`` never raises and returns ``[]`` on a
    missing token or any failure; ids are allowlist-filtered again by
    ``SettingsLLM``. The token is never part of the result.

    Args:
        provider: The effective LLM provider for the settings response.

    Returns:
        The listed model IDs, or ``[]``.
    """
    if provider != "infomaniak" or _agent is None:
        return []

    from admino.llm_infomaniak import InfomaniakClient

    client = _agent._llm
    if not isinstance(client, InfomaniakClient):
        return []
    return await client.list_models()


async def _check_llm_reachable() -> bool:
    """Return whether the active LLM provider looks reachable.

    For ``vllm`` this is True iff the ``/models`` probe returns a non-empty
    list within a short timeout. For cloud providers this returns True (setup
    problems such as a missing key surface as chat replies). Never raises.

    Returns:
        True if the provider is reachable (or is a cloud provider), else False.
    """
    if _config is None:
        return False
    if _config.llm.provider == "vllm":
        return bool(await _get_vllm_available_models())
    return True


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


async def health_check(request: Request) -> dict[str, str] | JSONResponse:
    """Handle GET /health — public (no session): up or degraded, nothing else.

    Checks database connectivity only: no LLM probe, no config. The provider,
    model and LLM reachability are for the Super Admin, on
    ``GET /api/platform/diagnostics``.

    Args:
        request: The incoming request (the client IP for the rate limit).

    Returns:
        200 ``{"status": "ok"}``, or 503 ``{"status": "degraded"}`` when the
        database is unreachable.

    Raises:
        HTTPException: 429 when the client IP is rate-limited (before the
            database check).
    """
    _check_rate_limit("/health", f"ip:{_client_ip(request)}")

    from admino.database import check_health

    if not await check_health():
        return JSONResponse(status_code=503, content={"status": "degraded"})
    return {"status": "ok"}


async def get_platform_diagnostics(principal: _PrincipalDep) -> PlatformDiagnosticsResponse:
    """Handle GET /api/platform/diagnostics — the LLM setup and statuses (Super Admin).

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        PlatformDiagnosticsResponse: the database status, the active provider
        and model, and whether the LLM looks reachable.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.PLATFORM_DIAGNOSTICS_VIEW`` (both before any probe).
    """
    _check_rate_limit("/api/platform/diagnostics", _user_caller(principal))
    if not can(principal, Capability.PLATFORM_DIAGNOSTICS_VIEW):
        raise HTTPException(status_code=403, detail="Forbidden")
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    from admino.database import check_health

    db_ok = await check_health()
    return PlatformDiagnosticsResponse(
        status="ok" if db_ok else "degraded",
        provider=_config.llm.provider,
        model=_config.llm.active_model_name or None,
        llm_reachable=await _check_llm_reachable(),
    )


# ---------------------------------------------------------------------------
# Auth route handlers
# ---------------------------------------------------------------------------


def _set_session_cookie(response: Response, result: auth.LoginResult) -> None:
    """Set the ``admino_session`` cookie of a new session (HttpOnly, SameSite=Strict, Path=/,
    Max-Age = the session policy's lifetime, Secure iff ``server.cookie_secure``)."""
    response.set_cookie(
        key=sessions.SESSION_COOKIE_NAME,
        value=result.token,
        max_age=result.max_age_seconds,
        path="/",
        secure=_config.server.cookie_secure if _config is not None else True,
        httponly=True,
        samesite="strict",
    )


def _clear_session_cookie(response: Response) -> None:
    """Make the browser drop the ``admino_session`` cookie (Max-Age=0)."""
    response.delete_cookie(
        key=sessions.SESSION_COOKIE_NAME,
        path="/",
        secure=_config.server.cookie_secure if _config is not None else True,
        httponly=True,
        samesite="strict",
    )


async def post_login(request: Request, body: LoginRequest) -> Response:
    """Handle POST /api/auth/login — email/password login (public).

    Rate-limited per client IP, then throttled per account and per client IP
    (``auth.login``: a progressive delay from the third failure, a lockout at
    the stored threshold, GH-160). On success opens a server-side session and
    answers 204 with the ``admino_session`` cookie (HttpOnly,
    SameSite=Strict, Path=/, Max-Age = the lifetime of the account's session
    policy, Secure iff ``server.cookie_secure``). Every failure cause
    (unknown email, wrong password, inactive account or organization, a
    locked account or IP) is the same 401, and no cookie is set.

    Args:
        request: The incoming request (client IP and User-Agent for the session).
        body: Validated LoginRequest; the password is a SecretStr.

    Returns:
        An empty 204 response carrying the session cookie.

    Raises:
        HTTPException: 401 on any login failure, 429 when rate-limited.

    Security notes:
        The email, password and token are never logged or echoed; the 401 is
        identical for every cause, a lockout included (no user enumeration).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/login", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        result = await auth.login(
            get_pool(),
            email=body.email,
            password=body.password.get_secret_value(),
            ip=request.client.host if request.client is not None else None,
            user_agent=request.headers.get("user-agent"),
        )
    except auth.LoginFailedError:
        raise HTTPException(status_code=401, detail=auth.LOGIN_FAILED_MESSAGE) from None

    response = Response(status_code=204)
    _set_session_cookie(response, result)
    return response


async def _request_reset_in_background(*, email: str, public_url: str, ip: str | None) -> None:
    """Run ``password_reset.request_reset`` after the 202 has been sent.

    A failure can't reach the caller any more (and must not: it would tell
    whether the account exists), so it is logged by exception class name only:
    no message text, no traceback, no email.
    """
    from admino.database import get_pool

    try:
        await password_reset.request_reset(get_pool(), email=email, public_url=public_url, ip=ip)
    except Exception as exc:
        logger.error("Password reset request failed (%s).", type(exc).__name__)


async def post_password_reset(request: Request, body: PasswordResetRequest) -> Response:
    """Handle POST /api/auth/password-reset — email a password reset link (public).

    Rate-limited per client IP. A client IP that the brute-force protection
    has locked gets 429 before anything is queued; any other waits out its
    IP's progressive delay (the request itself never counts as a failure).
    Then it always answers an empty 202: the account lookup, the token and the
    email happen in a background task after the response, so the answer is
    the same, and as fast, for every email.

    Args:
        request: The incoming request (the client IP for the throttle and the
            audit event).
        body: Validated PasswordResetRequest.

    Returns:
        An empty 202 response carrying the background task.

    Raises:
        HTTPException: 429 when rate-limited or when the client IP is locked.

    Security notes:
        The link base is ``server.public_url``, never a request header. The
        email is never logged or echoed.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/password-reset", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    ip = request.client.host if request.client is not None else None
    if not await login_throttle.admit(get_pool(), ip=ip):
        raise HTTPException(status_code=429, detail=login_throttle.TOO_MANY_ATTEMPTS_MESSAGE)

    return Response(
        status_code=202,
        background=BackgroundTask(
            _request_reset_in_background,
            email=body.email,
            public_url=_config.server.public_url,
            ip=ip,
        ),
    )


async def _throttled_link[T](
    request: Request, work: Callable[[], Awaitable[T]], *, unusable: type[Exception]
) -> T:
    """Run a public link route's work under the client IP's login throttle (GH-157).

    The link routes (password reset confirm, invitation details and accept)
    share the login's per-IP failure counter. A locked IP gets 429 before
    ``work`` runs, so no token or account is looked up and nothing is written.
    Otherwise the attempt reserves one failure and waits out the progressive
    delay first. ``unusable`` (a link that can't be used) keeps the failure,
    and the one at the lockout threshold locks the IP (audited as
    ``login.lockout``); a result, or a password-policy refusal (the link was
    usable), releases it. Any other error keeps it (fail closed). Every
    exception is re-raised for the route to map.

    Args:
        request: The incoming request (the client IP).
        work: Starts the route's service call.
        unusable: The service's exception for a link that can't be used.

    Returns:
        What ``work`` returned.

    Raises:
        HTTPException: 429 when the client IP is locked.
    """
    from admino.database import get_pool

    pool = get_pool()
    ip = request.client.host if request.client is not None else None
    attempt = await login_throttle.begin(pool, email=None, ip=ip)
    if attempt.locked:
        raise HTTPException(status_code=429, detail=login_throttle.TOO_MANY_ATTEMPTS_MESSAGE)
    try:
        result = await work()
    except unusable:
        await login_throttle.fail(pool, attempt, ip=ip)
        raise
    except passwords.PasswordPolicyError:
        await login_throttle.succeed(pool, attempt)
        raise
    await login_throttle.succeed(pool, attempt)
    return result


async def post_password_reset_confirm(
    request: Request, body: PasswordResetConfirmRequest
) -> Response:
    """Handle POST /api/auth/password-reset/confirm — set a new password (public).

    Rate-limited per client IP, then throttled by the client IP's login
    failure counter (``_throttled_link``): a locked IP gets 429 before the
    token is looked up, an unusable link counts as a failure. On success the
    password is changed and every session of the account ends, this browser's
    included: answers 204 and clears the session cookie.

    Args:
        request: The incoming request (the client IP for the throttle and the
            audit event).
        body: Validated PasswordResetConfirmRequest; token and password are SecretStr.

    Returns:
        An empty 204 response that clears the session cookie, or a 422
        ``{"detail": <policy message>, "reason": <reason>}`` when the password
        policy refuses the new password (the link stays usable).

    Raises:
        HTTPException: 400 for every link that can't be used (malformed,
            unknown, expired, used or replaced token, or an account that may no
            longer log in), 429 when rate-limited or when the client IP is
            locked.

    Security notes:
        The token and password are never logged or echoed.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/password-reset/confirm", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        await _throttled_link(
            request,
            lambda: password_reset.confirm_reset(
                get_pool(),
                token=body.token.get_secret_value(),
                new_password=body.new_password.get_secret_value(),
                ip=request.client.host if request.client is not None else None,
            ),
            unusable=password_reset.InvalidResetTokenError,
        )
    except password_reset.InvalidResetTokenError:
        raise HTTPException(
            status_code=400, detail=password_reset.INVALID_RESET_TOKEN_MESSAGE
        ) from None
    except passwords.PasswordPolicyError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc), "reason": exc.reason})

    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


async def post_logout(
    request: Request,
    session: _SessionDep,
) -> Response:
    """Handle POST /api/auth/logout — end the current session.

    Only the session of this cookie ends: its row is deleted (the user's other
    devices stay logged in). Answers 204 and clears the cookie. Not audited.

    Args:
        request: The incoming request (its session cookie's session ends).
        session: The resolved session (401 without one).

    Returns:
        An empty 204 response that clears the session cookie.
    """
    _check_rate_limit("/api/auth/logout", _user_caller(session.principal))

    from admino.database import get_pool

    token = request.cookies.get(sessions.SESSION_COOKIE_NAME)
    if token:
        await auth.logout(get_pool(), token)

    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


async def get_me(
    session: _SessionDep,
) -> MeResponse:
    """Handle GET /api/auth/me — the logged-in account and its languages.

    Every value comes from the resolved session (the database), never from the
    request.

    Args:
        session: The resolved session (401 without one).

    Returns:
        MeResponse with the principal's ids, kind, role and languages.
    """
    principal = session.principal
    _check_rate_limit("/api/auth/me", _user_caller(principal))
    return MeResponse(
        user_id=principal.user_id,
        kind=principal.kind,
        org_id=principal.org_id,
        role=principal.role,
        ui_language=session.ui_language,
        response_language=session.response_language,
    )


# ---------------------------------------------------------------------------
# Session management route handlers (GH-152)
# ---------------------------------------------------------------------------


async def get_my_sessions(session: _SessionDep) -> SessionListResponse:
    """Handle GET /api/me/sessions — the caller's live sessions.

    Args:
        session: The resolved session (401 without one); its session is marked
            ``current``.

    Returns:
        SessionListResponse, the most recently active session first. No token
        or token hash is included.

    Raises:
        HTTPException: 403 without ``Capability.ACCOUNT_MANAGE``, 429 when
            rate-limited.
    """
    principal = session.principal
    if not can(principal, Capability.ACCOUNT_MANAGE):
        raise HTTPException(status_code=403, detail="Forbidden")
    _check_rate_limit("/api/me/sessions/get", _user_caller(principal))

    from admino.database import get_pool

    return SessionListResponse(
        sessions=await session_management.list_user_sessions(
            get_pool(), user_id=principal.user_id, current_session_id=session.session_id
        )
    )


async def delete_my_session(
    request: Request,
    session: _SessionDep,
    session_id: UUID,
) -> Response:
    """Handle DELETE /api/me/sessions/{session_id} — end one of the caller's sessions.

    The session's row is deleted and ``session.revoke`` is recorded. Ending the
    request's own session also clears the cookie.

    Args:
        request: The incoming request (the client IP for the audit event).
        session: The resolved session (401 without one).
        session_id: The session to end (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 403 without ``Capability.ACCOUNT_MANAGE``; 404 when the
            session doesn't exist or isn't the caller's (the same body either
            way); 429 when rate-limited.
    """
    principal = session.principal
    if not can(principal, Capability.ACCOUNT_MANAGE):
        raise HTTPException(status_code=403, detail="Forbidden")
    _check_rate_limit("/api/me/sessions/delete", _user_caller(principal))

    from admino.database import get_pool

    try:
        await session_management.revoke_own_session(
            get_pool(),
            principal=principal,
            session_id=session_id,
            ip=request.client.host if request.client is not None else None,
        )
    except session_management.SessionNotFoundError:
        raise HTTPException(
            status_code=404, detail=session_management.SESSION_NOT_FOUND_MESSAGE
        ) from None

    response = Response(status_code=204)
    if session_id == session.session_id:
        _clear_session_cookie(response)
    return response


async def post_org_user_logout(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
) -> Response:
    """Handle POST /api/org/users/{user_id}/logout — log a user of the org out everywhere.

    Every session of the user is deleted and ``session.force_logout`` is
    recorded (also when there was none).

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        user_id: The user to log out (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't a member of the caller's org, is deleted or doesn't
            exist (the same body either way); 429 when rate-limited.
    """
    _check_rate_limit("/api/org/users/logout", _user_caller(principal))

    from admino.database import get_pool

    try:
        await session_management.force_logout(
            get_pool(),
            actor=principal,
            user_id=user_id,
            ip=request.client.host if request.client is not None else None,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except accounts.UserNotInOrgError:
        raise HTTPException(status_code=404, detail="User not found") from None
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Account self-service route handlers (GH-166)
# ---------------------------------------------------------------------------


async def get_my_account(principal: _PrincipalDep) -> MyAccountResponse:
    """Handle GET /api/me — the caller's own profile, languages, timezone and instructions.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        MyAccountResponse read from the caller's own users row.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work);
            404 when the account is deleted or missing.
    """
    _check_rate_limit("/api/me/get", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    try:
        return await my_account.get_account(get_pool(), principal=principal)
    except my_account.AccountNotFoundError:
        raise HTTPException(status_code=404, detail=my_account.ACCOUNT_NOT_FOUND_MESSAGE) from None


async def patch_my_account(principal: _PrincipalDep, body: MyAccountPatch) -> MyAccountResponse:
    """Handle PATCH /api/me — change the caller's own name, languages, timezone or instructions.

    Only the given fields change; not audited (the user's own preferences).

    Args:
        principal: The logged-in principal (401 without a session).
        body: Validated MyAccountPatch (422 without echo otherwise).

    Returns:
        MyAccountResponse with the stored values after the change.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work);
            404 when the account is deleted or missing.
    """
    _check_rate_limit("/api/me/patch", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    try:
        return await my_account.update_account(get_pool(), principal=principal, patch=body)
    except my_account.AccountNotFoundError:
        raise HTTPException(status_code=404, detail=my_account.ACCOUNT_NOT_FOUND_MESSAGE) from None


async def post_my_password(
    request: Request, principal: _PrincipalDep, body: PasswordChangeRequest
) -> Response:
    """Handle POST /api/me/password — change the caller's own password.

    The new password must pass the policy (checked first), then the current
    one is re-checked through the login throttle. On success every session of
    the caller ends, this browser's included (``password.change`` is
    recorded): answers 204 and clears the session cookie.

    Args:
        request: The incoming request (the client IP for the throttle and the
            audit event).
        principal: The logged-in principal (401 without a session).
        body: Validated PasswordChangeRequest; both passwords are SecretStr.

    Returns:
        An empty 204 response that clears the session cookie, or a 422
        ``{"detail": <policy message>, "reason": <reason>}`` when the password
        policy refuses the new password (nothing changes).

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work);
            403 "Re-authentication failed." for a wrong current password or a
            locked account or IP (never 401: the session stays valid); 404
            when the account is deleted or missing.

    Security notes:
        The passwords are never logged or echoed. A failed audit write is a
        500 with the password and the sessions unchanged.
    """
    _check_rate_limit("/api/me/password", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    try:
        await my_account.change_password(
            get_pool(),
            principal=principal,
            current_password=body.current_password.get_secret_value(),
            new_password=body.new_password.get_secret_value(),
            ip=request.client.host if request.client is not None else None,
        )
    except my_account.AccountNotFoundError:
        raise HTTPException(status_code=404, detail=my_account.ACCOUNT_NOT_FOUND_MESSAGE) from None
    except my_account.WrongPasswordError:
        raise HTTPException(status_code=403, detail=_REAUTH_FAILED_DETAIL) from None
    except passwords.PasswordPolicyError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc), "reason": exc.reason})

    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Invitation route handlers (GH-153)
# ---------------------------------------------------------------------------

_EMAIL_TAKEN_BODY: Final = {
    "detail": "A user with this email already exists.",
    "reason": "email_taken",
}
_SEAT_LIMIT_BODY: Final = {"detail": invitations.SEAT_LIMIT_MESSAGE, "reason": "seat_limit"}


async def post_org_invitation(
    request: Request,
    session: _SessionDep,
    body: InvitationCreateRequest,
) -> InvitationSummary | JSONResponse:
    """Handle POST /api/org/invitations — an Org Admin invites an email into their org.

    The invited account gets the caller's session language (the email goes
    out in it), and the link is built from ``server.public_url`` only.

    Args:
        request: The incoming request (the client IP for the audit event).
        session: The resolved session (401 without one).
        body: Validated InvitationCreateRequest (the email and the member role).

    Returns:
        201 with the new invitation's InvitationSummary, or a 409 ``{"detail",
        "reason"}``: ``email_taken`` when a user with the email exists anywhere
        on the platform, ``seat_limit`` when the org has no free seat. A 409
        writes only the ``invitation.refuse`` audit event and spends one token
        of the caller's refused budget (shared with refused email changes).

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_INVITE``, 429 when
            rate-limited or when the caller has spent their refused budget
            (checked before any database work).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    principal = session.principal
    caller = _user_caller(principal)
    _check_rate_limit("/api/org/invitations/create", caller)
    if _budget_exhausted(_INVITE_REFUSED_ROUTE, caller):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from admino.database import get_pool

    try:
        return await invitations.create_invitation(
            get_pool(),
            actor=principal,
            email=body.email,
            role=body.role,
            language=session.ui_language,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except accounts.DuplicateEmailError:
        _spend_budget(_INVITE_REFUSED_ROUTE, caller)
        return JSONResponse(status_code=409, content=_EMAIL_TAKEN_BODY)
    except invitations.SeatLimitError:
        _spend_budget(_INVITE_REFUSED_ROUTE, caller)
        return JSONResponse(status_code=409, content=_SEAT_LIMIT_BODY)


async def get_org_invitations(principal: _PrincipalDep) -> InvitationListResponse:
    """Handle GET /api/org/invitations — the pending invitations of the caller's org.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        InvitationListResponse, the most recently sent first, expired ones
        flagged. No token, hash or link is included.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_VIEW``, 429 when
            rate-limited.
    """
    _check_rate_limit("/api/org/invitations/get", _user_caller(principal))

    from admino.database import get_pool

    try:
        pending = await invitations.list_invitations(get_pool(), actor=principal)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    return InvitationListResponse(invitations=pending)


async def delete_org_invitation(
    request: Request,
    principal: _PrincipalDep,
    invitation_id: UUID,
) -> Response:
    """Handle DELETE /api/org/invitations/{invitation_id} — revoke a pending invitation.

    The invited account is deleted with its invitation and queued email, which
    frees the email and the seat; ``invitation.revoke`` is recorded.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        invitation_id: The invitation (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_INVITE``; 404 for an
            unknown id, another org's or an accepted invitation (the same body
            either way); 429 when rate-limited.
    """
    _check_rate_limit("/api/org/invitations/revoke", _user_caller(principal))

    from admino.database import get_pool

    try:
        await invitations.revoke_invitation(
            get_pool(),
            actor=principal,
            invitation_id=invitation_id,
            ip=request.client.host if request.client is not None else None,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except invitations.InvitationNotFoundError:
        raise HTTPException(
            status_code=404, detail=invitations.INVITATION_NOT_FOUND_MESSAGE
        ) from None
    return Response(status_code=204)


async def post_org_invitation_resend(
    request: Request,
    principal: _PrincipalDep,
    invitation_id: UUID,
) -> InvitationSummary:
    """Handle POST /api/org/invitations/{invitation_id}/resend — send it again, new link.

    The token rotates (the old link stops working), the expiry restarts and a
    new email is queued; ``invitation.resend`` is recorded. No free seat is
    needed.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        invitation_id: The invitation (a UUID; anything else is a 422).

    Returns:
        The invitation's InvitationSummary with the new dates.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_INVITE``; 404 for an
            unknown id, another org's or an accepted invitation (the same body
            either way); 429 when rate-limited.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/org/invitations/resend", _user_caller(principal))

    from admino.database import get_pool

    try:
        return await invitations.resend_invitation(
            get_pool(),
            actor=principal,
            invitation_id=invitation_id,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except invitations.InvitationNotFoundError:
        raise HTTPException(
            status_code=404, detail=invitations.INVITATION_NOT_FOUND_MESSAGE
        ) from None


async def get_invitation_details(request: Request, token: str) -> InvitationDetails:
    """Handle GET /api/auth/invitations/{token} — what the acceptance page shows (public).

    Rate-limited per client IP, then throttled by the client IP's login
    failure counter (``_throttled_link``): a locked IP gets 429 before the
    token is looked up, an unusable link counts as a failure. The token is an
    unbounded path string on purpose: a malformed one gets the same 404 as an
    unknown one (never a 422), before any token lookup.

    Args:
        request: The incoming request (the client IP for the rate limit and
            the throttle).
        token: The token from the invitation link.

    Returns:
        InvitationDetails: the org name, the role and the email.

    Raises:
        HTTPException: 404 for every link that can't be used (one body), 429
            when rate-limited or when the client IP is locked.
    """
    _check_rate_limit("/api/auth/invitations/get", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        return await _throttled_link(
            request,
            lambda: invitations.get_invitation(get_pool(), token),
            unusable=invitations.InvalidInvitationError,
        )
    except invitations.InvalidInvitationError:
        raise HTTPException(
            status_code=404, detail=invitations.INVALID_INVITATION_MESSAGE
        ) from None


async def post_invitation_accept(
    request: Request, token: str, body: InvitationAcceptRequest
) -> Response:
    """Handle POST /api/auth/invitations/{token}/accept — accept and log in (public).

    Rate-limited per client IP, then throttled by the client IP's login
    failure counter (``_throttled_link``): a locked IP gets 429 before the
    token is looked up, an unusable link counts as a failure. On success the
    account is activated with the name and password, a session opens with the
    org's policy, and the answer is a 204 with the ``admino_session`` cookie,
    set exactly as by the login.

    Args:
        request: The incoming request (client IP and User-Agent for the session,
            the client IP for the throttle).
        token: The token from the invitation link (a malformed one is a 404).
        body: Validated InvitationAcceptRequest; the password is a SecretStr.

    Returns:
        An empty 204 response carrying the session cookie, or a 422
        ``{"detail": <policy message>, "reason": <reason>}`` when the password
        policy refuses the password (the link stays usable).

    Raises:
        HTTPException: 404 for every link that can't be used (one body), 429
            when rate-limited or when the client IP is locked.

    Security notes:
        The token, name and password are never logged or echoed.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/auth/invitations/accept", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        result = await _throttled_link(
            request,
            lambda: invitations.accept_invitation(
                get_pool(),
                token=token,
                name=body.name,
                password=body.password.get_secret_value(),
                ip=request.client.host if request.client is not None else None,
                user_agent=request.headers.get("user-agent"),
            ),
            unusable=invitations.InvalidInvitationError,
        )
    except invitations.InvalidInvitationError:
        raise HTTPException(
            status_code=404, detail=invitations.INVALID_INVITATION_MESSAGE
        ) from None
    except passwords.PasswordPolicyError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc), "reason": exc.reason})

    response = Response(status_code=204)
    _set_session_cookie(response, result)
    return response


# ---------------------------------------------------------------------------
# Org Admin user management route handlers (GH-164)
# ---------------------------------------------------------------------------

_INVALID_USER_STATUS_BODY: Final = {
    "detail": org_users.INVALID_USER_STATUS_MESSAGE,
    "reason": "invalid_status",
}
# The providers of the access-token cache a deleted user's entries are dropped from.
_OAUTH_PROVIDERS: Final[tuple[OAuthProvider, ...]] = ("google", "microsoft")


async def _org_user_change[T](change: Awaitable[T]) -> T | JSONResponse:
    """Await one ``org_users`` action and map its refusals to responses.

    ``accounts.DuplicateEmailError`` and audit failures propagate.

    Returns:
        What the action returned, or a 409 ``{"detail", "reason"}``:
        ``last_admin`` when it would leave the org without an active Org
        Admin, ``seat_limit`` when a reactivation finds no free seat,
        ``invalid_status`` when the user's status doesn't allow it.

    Raises:
        HTTPException: 403 without the action's capability; 404 when the user
            isn't an active or deactivated member of the caller's org (one body
            for an unknown id, another org's user, an invited or a deleted
            account).
    """
    try:
        return await change
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except accounts.UserNotInOrgError:
        raise HTTPException(status_code=404, detail=org_users.USER_NOT_FOUND_MESSAGE) from None
    except accounts.LastAdminError as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc), "reason": "last_admin"})
    except invitations.SeatLimitError:
        return JSONResponse(status_code=409, content=_SEAT_LIMIT_BODY)
    except org_users.InvalidUserStatusError:
        return JSONResponse(status_code=409, content=_INVALID_USER_STATUS_BODY)


async def _forget_user(user_id: UUID) -> None:
    """Drop a deleted user's in-memory state; other users' entries stay.

    Their pending confirmations and chat locks in ``_chat_runtime``
    (``ChatRuntime.forget_user``; their persisted chats go with the users row
    by CASCADE), their pending OAuth states and their cached access tokens of
    both providers.
    """
    _chat_runtime.forget_user(user_id)
    states = [state for state, entry in _oauth_pending_states.items() if entry.user_id == user_id]
    for state in states:
        del _oauth_pending_states[state]
    for provider in _OAUTH_PROVIDERS:
        await access_tokens.invalidate(user_id, provider)


async def get_org_users(principal: _PrincipalDep) -> OrgUserListResponse:
    """Handle GET /api/org/users — the users of the caller's org and its seat usage.

    Invited accounts aren't listed here (GET /api/org/invitations lists them),
    but they take a seat: ``seats.used`` counts the active and invited users,
    ``seats.limit`` is the org's seats (GH-165).

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        OrgUserListResponse: the active and deactivated users, oldest first
        (each user's id, name, email, role, status, created date and last
        login), and the org's seat usage.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_VIEW``, 429 when
            rate-limited.
    """
    _check_rate_limit("/api/org/users/get", _user_caller(principal))

    from admino.database import get_pool

    try:
        return OrgUserListResponse(
            users=await org_users.list_org_users(get_pool(), actor=principal),
            seats=await org_users.seat_usage(get_pool(), actor=principal),
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None


async def patch_org_user(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
    body: OrgUserPatch,
) -> OrgUserSummary | JSONResponse:
    """Handle PATCH /api/org/users/{user_id} — change a user's role, name or email.

    An email change emails the old address a notice and cancels the user's
    pending reset link. Values equal to the stored ones are no change: nothing
    is written or audited.

    Args:
        request: The incoming request (the client IP for the audit events).
        principal: The logged-in principal (401 without a session).
        user_id: The user to change (a UUID; anything else is a 422).
        body: Validated OrgUserPatch (at least one of role, name and email).

    Returns:
        The user's OrgUserSummary after the change, or a 409 ``{"detail",
        "reason"}``: ``last_admin`` when it would demote the org's last active
        Org Admin, ``email_taken`` when a user with the email exists anywhere
        on the platform. ``email_taken`` changes nothing, records only the
        content-free ``user.profile_change`` refusal and spends one token of the
        caller's refused budget (shared with refused invitation sends).

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE`` (and, for a
            role, ``Capability.ORG_USERS_ROLE_CHANGE``); 404 when the user isn't
            an active or deactivated member of the caller's org (one body); 429
            when rate-limited or, for a body with an email, when the caller has
            spent their refused budget (checked before any database work).
    """
    caller = _user_caller(principal)
    _check_rate_limit("/api/org/users/patch", caller)
    if body.email is not None and _budget_exhausted(_INVITE_REFUSED_ROUTE, caller):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from admino.database import get_pool

    try:
        return await _org_user_change(
            org_users.update_org_user(
                get_pool(),
                actor=principal,
                user_id=user_id,
                patch=body,
                ip=request.client.host if request.client is not None else None,
            )
        )
    except accounts.DuplicateEmailError:
        _spend_budget(_INVITE_REFUSED_ROUTE, caller)
        return JSONResponse(status_code=409, content=_EMAIL_TAKEN_BODY)


async def post_org_user_deactivate(
    request: Request,
    response: Response,
    principal: _PrincipalDep,
    user_id: UUID,
) -> OrgUserSummary | JSONResponse:
    """Handle POST /api/org/users/{user_id}/deactivate — deactivate an active user.

    Every session of the user ends at once and they are emailed; their
    connections, notes and settings are kept. Deactivating oneself also
    clears the cookie.

    Args:
        request: The incoming request (the client IP for the audit event).
        response: The response the cleared cookie is set on.
        principal: The logged-in principal (401 without a session).
        user_id: The user to deactivate (a UUID; anything else is a 422).

    Returns:
        The user's OrgUserSummary (status "deactivated"), or a 409
        ``last_admin`` for the org's last active Org Admin, ``invalid_status``
        when the user is already deactivated.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't an active or deactivated member of the caller's org
            (one body); 429 when rate-limited (the bucket it shares with
            reactivating).
    """
    _check_rate_limit("/api/org/users/status", _user_caller(principal))

    from admino.database import get_pool

    result = await _org_user_change(
        org_users.deactivate_org_user(
            get_pool(),
            actor=principal,
            user_id=user_id,
            ip=request.client.host if request.client is not None else None,
        )
    )
    if user_id == principal.user_id and not isinstance(result, JSONResponse):
        _clear_session_cookie(response)
    return result


async def post_org_user_reactivate(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
) -> OrgUserSummary | JSONResponse:
    """Handle POST /api/org/users/{user_id}/reactivate — reactivate a deactivated user.

    Needs a free seat (active and invited users count); the user is emailed a
    login link built from ``server.public_url`` only.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        user_id: The user to reactivate (a UUID; anything else is a 422).

    Returns:
        The user's OrgUserSummary (status "active"), or a 409 ``seat_limit``
        when the org has no free seat, ``invalid_status`` when the user is
        active.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't an active or deactivated member of the caller's org
            (one body); 429 when rate-limited (the bucket it shares with
            deactivating).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/org/users/status", _user_caller(principal))

    from admino.database import get_pool

    return await _org_user_change(
        org_users.reactivate_org_user(
            get_pool(),
            actor=principal,
            user_id=user_id,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def delete_org_user(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
) -> Response:
    """Handle DELETE /api/org/users/{user_id} — delete a user's account.

    The account goes with its sessions, OAuth connections, notes, settings and
    chats; then the server forgets the user's in-memory state (pending
    confirmations and chat locks, OAuth states, cached access tokens).
    Deleting oneself also clears the cookie. A refused delete forgets nothing.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        user_id: The user to delete (a UUID; anything else is a 422).

    Returns:
        An empty 204 response, or a 409 ``last_admin`` for the org's last
        active Org Admin.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't an active or deactivated member of the caller's org
            (one body); 429 when rate-limited.
    """
    _check_rate_limit("/api/org/users/delete", _user_caller(principal))

    from admino.database import get_pool

    result = await _org_user_change(
        org_users.delete_org_user(
            get_pool(),
            actor=principal,
            user_id=user_id,
            ip=request.client.host if request.client is not None else None,
        )
    )
    if isinstance(result, JSONResponse):
        return result
    await _forget_user(user_id)
    response = Response(status_code=204)
    if user_id == principal.user_id:
        _clear_session_cookie(response)
    return response


async def post_org_user_password_reset(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
) -> Response:
    """Handle POST /api/org/users/{user_id}/password-reset — email the user a reset link.

    The password reset email of GH-151, its link built from
    ``server.public_url`` only; the token never reaches the Org Admin.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        user_id: The user who gets the link (a UUID; anything else is a 422).

    Returns:
        An empty 202 response, or a 409 ``invalid_status`` when the user is
        deactivated.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't an active or deactivated member of the caller's org
            (one body); 429 when rate-limited.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/org/users/password-reset", _user_caller(principal))

    from admino.database import get_pool

    result = await _org_user_change(
        org_users.trigger_password_reset(
            get_pool(),
            actor=principal,
            user_id=user_id,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    )
    if isinstance(result, JSONResponse):
        return result
    return Response(status_code=202)


# ---------------------------------------------------------------------------
# Platform organization route handlers (GH-154), Super Admin only
# ---------------------------------------------------------------------------

_INVALID_ORG_STATUS_BODY: Final = {
    "detail": organizations.INVALID_STATUS_MESSAGE,
    "reason": "invalid_status",
}


async def _org_change(change: Awaitable[OrgSummary]) -> OrgSummary | JSONResponse:
    """Await one organizations change and map its refusals to responses.

    Returns:
        The org's OrgSummary after the change, or a 409 ``{"detail", "reason":
        "invalid_status"}`` when the org's status doesn't allow it.

    Raises:
        HTTPException: 403 without the change's capability, 404 for an
            unknown org.
    """
    try:
        return await change
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except organizations.OrgNotFoundError:
        raise HTTPException(status_code=404, detail=organizations.ORG_NOT_FOUND_MESSAGE) from None
    except organizations.InvalidOrgStatusError:
        return JSONResponse(status_code=409, content=_INVALID_ORG_STATUS_BODY)


async def get_platform_orgs(principal: _PrincipalDep) -> OrgListResponse:
    """Handle GET /api/platform/orgs — every organization's metadata.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        OrgListResponse: every org, whatever its status, oldest first.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIFECYCLE_MANAGE``, 429 when
            rate-limited.
    """
    _check_rate_limit("/api/platform/orgs/get", _user_caller(principal))

    from admino.database import get_pool

    try:
        orgs = await organizations.list_orgs(get_pool(), actor=principal)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    return OrgListResponse(organizations=orgs)


async def post_platform_org(
    request: Request,
    session: _SessionDep,
    body: OrgCreateRequest,
) -> OrgCreateResponse | JSONResponse:
    """Handle POST /api/platform/orgs — create an org and invite its first Org Admin.

    The invited Org Admin gets the caller's session language (the email goes
    out in it), and the link is built from ``server.public_url`` only. The
    response carries neither the token nor the link.

    Args:
        request: The incoming request (the client IP for the audit events).
        session: The resolved session (401 without one).
        body: Validated OrgCreateRequest.

    Returns:
        201 with the new OrgSummary and the InvitationSummary, or a 409
        ``{"detail", "reason": "email_taken"}`` when a user with the email
        exists anywhere on the platform (nothing is written).

    Raises:
        HTTPException: 403 without ``Capability.ORG_CREATE``, 429 when
            rate-limited (checked before any database work).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    principal = session.principal
    _check_rate_limit("/api/platform/orgs/create", _user_caller(principal))

    from admino.database import get_pool

    try:
        created = await organizations.create_org(
            get_pool(),
            actor=principal,
            request=body,
            language=session.ui_language,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
            queue_email=True,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except accounts.DuplicateEmailError:
        return JSONResponse(status_code=409, content=_EMAIL_TAKEN_BODY)
    # The one-time link stays out of the response: it travels in the email only.
    return OrgCreateResponse(organization=created.organization, invitation=created.invitation)


async def patch_platform_org_limits(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
    body: OrgLimitsPatch,
) -> OrgSummary | JSONResponse:
    """Handle PATCH /api/platform/orgs/{org_id}/limits — change an org's plan limits.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).
        body: Validated OrgLimitsPatch (at least one limit).

    Returns:
        The org's OrgSummary, or a 409 ``invalid_status`` while a deletion is
        pending.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIMITS_MANAGE``; 404 for
            an unknown org; 429 when rate-limited.
    """
    _check_rate_limit("/api/platform/orgs/limits", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.update_limits(
            get_pool(),
            actor=principal,
            org_id=org_id,
            patch=body,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def post_platform_org_deactivate(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
) -> OrgSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/deactivate — deactivate an active org.

    Every session of the org's users ends at once; its content is kept.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).

    Returns:
        The org's OrgSummary, or a 409 ``invalid_status`` unless it is active.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIFECYCLE_MANAGE``; 404 for
            an unknown org; 429 when rate-limited (the bucket it shares with
            reactivating).
    """
    _check_rate_limit("/api/platform/orgs/status", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.deactivate_org(
            get_pool(),
            actor=principal,
            org_id=org_id,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def post_platform_org_reactivate(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
) -> OrgSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/reactivate — reactivate a deactivated org.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).

    Returns:
        The org's OrgSummary, or a 409 ``invalid_status`` unless it is
        deactivated.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIFECYCLE_MANAGE``; 404 for
            an unknown org; 429 when rate-limited (the bucket it shares with
            deactivating).
    """
    _check_rate_limit("/api/platform/orgs/status", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.reactivate_org(
            get_pool(),
            actor=principal,
            org_id=org_id,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def post_platform_org_deletion(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
) -> OrgSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/deletion — schedule an org's deletion.

    The org is purged after the grace period; its users' sessions end and its
    active Org Admins are emailed.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).

    Returns:
        The org's OrgSummary with its deletion dates, or a 409
        ``invalid_status`` when a deletion is already pending.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIFECYCLE_MANAGE``; 404 for
            an unknown org; 429 when rate-limited (the bucket it shares with
            cancelling).
    """
    _check_rate_limit("/api/platform/orgs/deletion", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.schedule_deletion(
            get_pool(),
            actor=principal,
            org_id=org_id,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def delete_platform_org_deletion(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
) -> OrgSummary | JSONResponse:
    """Handle DELETE /api/platform/orgs/{org_id}/deletion — cancel a pending deletion.

    The org becomes deactivated, never active: reactivating is a separate step.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).

    Returns:
        The org's OrgSummary, or a 409 ``invalid_status`` when no deletion is
        pending.

    Raises:
        HTTPException: 403 without ``Capability.ORG_LIFECYCLE_MANAGE``; 404 for
            an unknown or purged org; 429 when rate-limited (the bucket it
            shares with scheduling).
    """
    _check_rate_limit("/api/platform/orgs/deletion", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.cancel_deletion(
            get_pool(),
            actor=principal,
            org_id=org_id,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def patch_platform_org_residency(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
    body: OrgResidencyPatch,
) -> OrgSummary | JSONResponse:
    """Handle PATCH /api/platform/orgs/{org_id}/residency — set the data residency policy.

    Recorded in the org's own log, so its admins see it.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The organization (a UUID; anything else is a 422).
        body: Validated OrgResidencyPatch (a strict bool).

    Returns:
        The org's OrgSummary, or a 409 ``invalid_status`` while a deletion is
        pending.

    Raises:
        HTTPException: 403 without ``Capability.ORG_RESIDENCY_MANAGE``; 404 for
            an unknown org; 429 when rate-limited.
    """
    _check_rate_limit("/api/platform/orgs/residency", _user_caller(principal))

    from admino.database import get_pool

    return await _org_change(
        organizations.set_residency(
            get_pool(),
            actor=principal,
            org_id=org_id,
            enabled=body.enabled,
            ip=request.client.host if request.client is not None else None,
        )
    )


# ---------------------------------------------------------------------------
# Platform user administration route handlers (GH-167), Super Admin only
# ---------------------------------------------------------------------------

_HAS_ACTIVE_ADMIN_BODY: Final = {
    "detail": platform_users.HAS_ACTIVE_ADMIN_MESSAGE,
    "reason": "has_active_admin",
}


async def _platform_user_change[T](
    change: Awaitable[T], *, refused_caller: str | None = None
) -> T | JSONResponse:
    """Await one ``platform_users`` action and map its refusals to responses.

    Audit failures propagate (a 500 with nothing changed).

    Args:
        change: The action.
        refused_caller: The caller whose refused budget an ``email_taken`` or
            ``seat_limit`` refusal spends one token of (a re-invite with an
            email); None spends nothing.

    Returns:
        What the action returned, or a 409 ``{"detail", "reason"}``:
        ``last_admin`` when it would leave the org without an active Org
        Admin, ``invalid_status`` when the user's or the org's status doesn't
        allow it, ``seat_limit`` when the org has no free seat,
        ``email_taken`` when a user with the replacement email exists anywhere
        on the platform, ``has_active_admin`` when a re-invite finds an active
        Org Admin.

    Raises:
        HTTPException: 403 without the action's capability; 404 for an unknown
            org, or when the user isn't a non-deleted account of the path's org
            (one body for an unknown id, another org's user, a deleted account
            and a Super Admin).
    """
    try:
        return await change
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except organizations.OrgNotFoundError:
        raise HTTPException(status_code=404, detail=organizations.ORG_NOT_FOUND_MESSAGE) from None
    except accounts.UserNotInOrgError:
        raise HTTPException(status_code=404, detail=org_users.USER_NOT_FOUND_MESSAGE) from None
    except accounts.LastAdminError as exc:
        return JSONResponse(status_code=409, content={"detail": str(exc), "reason": "last_admin"})
    except org_users.InvalidUserStatusError:
        return JSONResponse(status_code=409, content=_INVALID_USER_STATUS_BODY)
    except organizations.InvalidOrgStatusError:
        return JSONResponse(status_code=409, content=_INVALID_ORG_STATUS_BODY)
    except platform_users.OrgHasActiveAdminError:
        return JSONResponse(status_code=409, content=_HAS_ACTIVE_ADMIN_BODY)
    except (invitations.SeatLimitError, accounts.DuplicateEmailError) as exc:
        if refused_caller is not None:
            _spend_budget(_INVITE_REFUSED_ROUTE, refused_caller)
        if isinstance(exc, accounts.DuplicateEmailError):
            return JSONResponse(status_code=409, content=_EMAIL_TAKEN_BODY)
        return JSONResponse(status_code=409, content=_SEAT_LIMIT_BODY)


async def get_platform_org_users(
    principal: _PrincipalDep, org_id: UUID
) -> PlatformUserListResponse:
    """Handle GET /api/platform/orgs/{org_id}/users — an org's accounts.

    Read-only: nothing is written or audited.

    Args:
        principal: The logged-in principal (401 without a session).
        org_id: The organization, in any status (a UUID; anything else is a 422).

    Returns:
        PlatformUserListResponse: the org's active, deactivated and invited
        accounts, oldest first (each one's id, name, email, role, status,
        created date and last login); account metadata only.

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_ORG_METADATA_VIEW``;
            404 for an unknown org; 429 when rate-limited.
    """
    _check_rate_limit("/api/platform/orgs/users/get", _user_caller(principal))

    from admino.database import get_pool

    try:
        users = await platform_users.list_users(get_pool(), actor=principal, org_id=org_id)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except organizations.OrgNotFoundError:
        raise HTTPException(status_code=404, detail=organizations.ORG_NOT_FOUND_MESSAGE) from None
    return PlatformUserListResponse(users=users)


async def get_platform_org_metadata(principal: _PrincipalDep, org_id: UUID) -> OrgMetadata:
    """Handle GET /api/platform/orgs/{org_id}/metadata — an org's seats and counts.

    Read-only: nothing is written or audited.

    Args:
        principal: The logged-in principal (401 without a session).
        org_id: The organization, in any status (a UUID; anything else is a 422).

    Returns:
        OrgMetadata: the seats used (active and invited users) and the limit,
        the chats that aren't trashed, and the org's attachments (file count
        and bytes used, trashed ones included); counts and sizes only.

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_ORG_METADATA_VIEW``;
            404 for an unknown org; 429 when rate-limited.
    """
    _check_rate_limit("/api/platform/orgs/metadata/get", _user_caller(principal))

    from admino.database import get_pool

    try:
        return await platform_users.org_metadata(get_pool(), actor=principal, org_id=org_id)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except organizations.OrgNotFoundError:
        raise HTTPException(status_code=404, detail=organizations.ORG_NOT_FOUND_MESSAGE) from None


async def post_platform_org_user_deactivate(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
    user_id: UUID,
) -> PlatformUserSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/users/{user_id}/deactivate — deactivate a user.

    Works in any org status. Every session of the user ends at once and they
    are emailed; their connections, notes and settings are kept. Recorded in
    the org's own log.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The user's organization (a UUID; anything else is a 422).
        user_id: The user to deactivate (a UUID; anything else is a 422).

    Returns:
        The user's PlatformUserSummary (status "deactivated"), or a 409
        ``last_admin`` for the org's last active Org Admin, ``invalid_status``
        when the user is deactivated or invited.

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_USERS_MANAGE``; 404
            for an unknown org or when the user isn't an account of that org
            (one body); 429 when rate-limited (the bucket it shares with
            reactivating).
    """
    _check_rate_limit("/api/platform/orgs/users/status", _user_caller(principal))

    from admino.database import get_pool

    return await _platform_user_change(
        platform_users.deactivate_user(
            get_pool(),
            actor=principal,
            org_id=org_id,
            user_id=user_id,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def post_platform_org_user_reactivate(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
    user_id: UUID,
) -> PlatformUserSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/users/{user_id}/reactivate — reactivate a user.

    Refused while the org's deletion is pending. Needs a free seat (active and
    invited users count); the user is emailed a login link built from
    ``server.public_url`` only. Recorded in the org's own log.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The user's organization (a UUID; anything else is a 422).
        user_id: The user to reactivate (a UUID; anything else is a 422).

    Returns:
        The user's PlatformUserSummary (status "active"), or a 409
        ``invalid_status`` while the org's deletion is pending or when the
        user is active or invited, ``seat_limit`` when the org has no free
        seat.

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_USERS_MANAGE``; 404
            for an unknown org or when the user isn't an account of that org
            (one body); 429 when rate-limited (the bucket it shares with
            deactivating).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/platform/orgs/users/status", _user_caller(principal))

    from admino.database import get_pool

    return await _platform_user_change(
        platform_users.reactivate_user(
            get_pool(),
            actor=principal,
            org_id=org_id,
            user_id=user_id,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    )


async def post_platform_org_user_password_reset(
    request: Request,
    principal: _PrincipalDep,
    org_id: UUID,
    user_id: UUID,
) -> Response:
    """Handle POST /api/platform/orgs/{org_id}/users/{user_id}/password-reset — email a reset link.

    The password reset email of GH-151, its link built from
    ``server.public_url`` only; the token and the link never reach the Super
    Admin. Recorded in the org's own log.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        org_id: The user's organization (a UUID; anything else is a 422).
        user_id: The user who gets the link (a UUID; anything else is a 422).

    Returns:
        An empty 202 response, or a 409 ``invalid_status`` unless the org and
        the user are active.

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_USERS_MANAGE``; 404
            for an unknown org or when the user isn't an account of that org
            (one body); 429 when rate-limited.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/platform/orgs/users/password-reset", _user_caller(principal))

    from admino.database import get_pool

    result = await _platform_user_change(
        platform_users.trigger_password_reset(
            get_pool(),
            actor=principal,
            org_id=org_id,
            user_id=user_id,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        )
    )
    if isinstance(result, JSONResponse):
        return result
    return Response(status_code=202)


async def post_platform_org_user_invitation(
    request: Request,
    session: _SessionDep,
    org_id: UUID,
    user_id: UUID,
    body: Annotated[PlatformReinviteRequest | None, Body()] = None,
) -> InvitationSummary | JSONResponse:
    """Handle POST /api/platform/orgs/{org_id}/users/{user_id}/invitation — re-invite an Org Admin.

    Only for an invited Org Admin of an active org that has no active Org
    Admin. Without an email (no body, ``{}`` or ``{"email": null}``) the
    invitation is sent again with a new link and the old one stops working.
    With an email the invited account is replaced by a new org_admin
    invitation to that address, in the caller's session language. Links are
    built from ``server.public_url`` only; the response carries neither the
    token nor the link. Recorded in the org's own log.

    Args:
        request: The incoming request (the client IP for the audit events).
        session: The resolved session (401 without one).
        org_id: The organization (a UUID; anything else is a 422).
        user_id: The invited Org Admin (a UUID; anything else is a 422).
        body: Validated PlatformReinviteRequest, or None (a resend).

    Returns:
        The InvitationSummary (the same invitation with its new dates for a
        resend, the new one for a replacement), or a 409 ``{"detail",
        "reason"}``: ``invalid_status`` unless the org is active and the user
        an invited Org Admin with a pending invitation, ``has_active_admin``
        when the org has an active Org Admin, ``email_taken`` when a user with
        the email exists anywhere on the platform, ``seat_limit`` when the org
        has no free seat. ``email_taken`` and ``seat_limit`` change nothing,
        record only the ``invitation.refuse`` audit event and spend one token
        of the caller's refused budget (shared with refused invitation sends
        and email changes).

    Raises:
        HTTPException: 403 without ``Capability.PLATFORM_USERS_MANAGE``; 404
            for an unknown org or when the user isn't an account of that org
            (one body); 429 when rate-limited or, for a body with an email,
            when the caller has spent their refused budget (checked before any
            database work).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    principal = session.principal
    caller = _user_caller(principal)
    _check_rate_limit("/api/platform/orgs/users/invitation", caller)
    email = body.email if body is not None else None
    if email is not None and _budget_exhausted(_INVITE_REFUSED_ROUTE, caller):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from admino.database import get_pool

    return await _platform_user_change(
        platform_users.reinvite_org_admin(
            get_pool(),
            actor=principal,
            org_id=org_id,
            user_id=user_id,
            email=email,
            language=session.ui_language,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        ),
        # Only a replacement probes an email: a resend never touches the budget.
        refused_caller=None if email is None else caller,
    )


async def _platform_run_settings() -> scoped_settings.StoredPlatformSettings:
    """The stored platform settings a chat run uses, read through the settings cache.

    The limits (GH-160) and the LLM retry limit (GH-242), read on every chat
    request, so a change applies to the next run without a restart.
    """
    from admino.database import get_pool

    return await scoped_settings.current_platform_settings(get_pool())


def _run_config(platform: scoped_settings.StoredPlatformSettings) -> AgentConfig:
    """The AgentConfig of one agent run.

    The stored tool-call, context and timeout limits, and the stored LLM retry
    limit (``llm.max_retries``, GH-242).
    """
    limits = platform.limits
    return AgentConfig(
        max_tool_calls=limits.max_tool_calls_per_message,
        max_context_messages=limits.max_context_messages,
        confirmation_timeout_s=float(limits.confirmation_timeout_s),
        llm_max_retries=platform.llm.max_retries,
    )


# ---------------------------------------------------------------------------
# Persisted chats (GH-176): the chat routes, the turn and the confirmation
# ---------------------------------------------------------------------------


def _chat_summary(chat: chats.ChatRecord) -> ChatSummary:
    """The API summary of a stored chat: metadata only, never a message."""
    return ChatSummary(
        id=chat.id,
        title=chat.title,
        title_source=chat.title_source,
        created_at=chat.created_at,
        last_activity_at=chat.last_activity_at,
    )


async def post_chat(principal: _ChatSenderDep, body: ChatCreateRequest) -> ChatSummary:
    """Handle POST /api/chats — create a chat of the caller.

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        body: Validated ChatCreateRequest. A JSON body is required (``{}`` is
            valid): no title is an untitled ``auto`` chat, a title (stripped)
            a ``user`` one. The org and the owner come from the session.

    Returns:
        201 with the new chat's ChatSummary.

    Raises:
        HTTPException: 429 when rate-limited.
    """
    _check_rate_limit("/api/chats/create", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    return _chat_summary(await chats.create_chat(get_pool(), tenant, title=body.title))


async def get_chats(
    principal: _ChatSenderDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> ChatListResponse:
    """Handle GET /api/chats — one page of the caller's chats, latest activity first.

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        limit: The page size, 1 to 100 (default 50).
        cursor: The previous page's ``next_cursor``; none for the first page.

    Returns:
        ChatListResponse: the caller's own chats that aren't in the trash
        (never a colleague's or another org's) by last activity then id, and
        the next page's cursor (None on the last page).

    Raises:
        HTTPException: 429 when rate-limited. A cursor that doesn't decode is
            a 422 ``invalid_cursor`` (``chats.InvalidCursorError``).
    """
    _check_rate_limit("/api/chats/list", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    page = await chats.list_chats(get_pool(), tenant, limit=limit, cursor=cursor)
    return ChatListResponse(
        chats=[_chat_summary(chat) for chat in page.chats], next_cursor=page.next_cursor
    )


async def get_chat_detail(
    principal: _ChatSenderDep,
    chat_id: UUID,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> ChatDetailResponse:
    """Handle GET /api/chats/{chat_id} — a chat of the caller with one page of messages.

    Expired confirmations are reaped first, so ``confirmation_status`` is
    ``pending`` (with ``pending_confirmation``) only for a live one in
    ``_chat_runtime``, ``expired`` when the latest message awaits a
    confirmation that is gone (expired, or lost in a restart), else ``none``.
    ``context`` (interim until #190) counts every message of the chat against
    the stored platform ``max_context_messages`` (the latest messages a run
    sends to the model). One ``chats.read_chat_detail`` read: the owner check
    runs once, and the latest status is read without its message (GH-266).
    Reading changes nothing.

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        chat_id: The chat (a UUID; anything else is a 422).
        limit: The page size, 1 to 100 (default 100).
        cursor: The previous page's ``next_cursor`` (earlier messages); none
            for the latest page.

    Returns:
        ChatDetailResponse: the summary, the page's messages in chronological
        order (sanitized content and tool-call summaries, never the raw tool
        inputs), the cursor of earlier messages, the confirmation state and
        the context.

    Raises:
        HTTPException: 429 when rate-limited. Another org's, a colleague's,
            a trashed and an unknown chat are the 404 ``chat_not_found``
            (``chats.ChatNotFoundError``); a cursor that doesn't decode is a
            422 ``invalid_cursor``.
    """
    _check_rate_limit("/api/chats/get", _user_caller(principal))
    _reap_expired_confirmations()

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    detail = await chats.read_chat_detail(get_pool(), tenant, chat_id, limit=limit, cursor=cursor)
    chat, page, message_count = detail.chat, detail.page, detail.message_count
    max_context = (await _platform_run_settings()).limits.max_context_messages
    pending = _chat_runtime.get_pending(chat.id)
    confirmation_status: Literal["none", "pending", "expired"] = "none"
    if pending is not None:
        confirmation_status = "pending"
    elif detail.latest_status == "awaiting_confirmation":
        confirmation_status = "expired"
    return ChatDetailResponse(
        id=chat.id,
        title=chat.title,
        title_source=chat.title_source,
        created_at=chat.created_at,
        last_activity_at=chat.last_activity_at,
        messages=[
            ChatMessageView.model_validate(message, from_attributes=True)
            for message in page.messages
        ],
        next_cursor=page.next_cursor,
        pending_confirmation=None if pending is None else _summarise_pending(pending),
        confirmation_status=confirmation_status,
        context=ChatContext(
            message_count=message_count,
            max_context_messages=max_context,
            truncated=message_count > max_context,
        ),
    )


async def patch_chat(
    principal: _ChatSenderDep, chat_id: UUID, body: ChatUpdateRequest
) -> ChatSummary:
    """Handle PATCH /api/chats/{chat_id} — rename a chat of the caller.

    The title becomes a ``user`` title; the last activity is unchanged, and
    the same title again changes nothing (idempotent).

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        chat_id: The chat (a UUID; anything else is a 422).
        body: Validated ChatUpdateRequest (the stripped title).

    Returns:
        The renamed chat's ChatSummary.

    Raises:
        HTTPException: 429 when rate-limited. A chat the caller can't reach is
            the 404 ``chat_not_found``.
    """
    _check_rate_limit("/api/chats/patch", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    return _chat_summary(await chats.rename_chat(get_pool(), tenant, chat_id, body.title))


async def delete_chat(request: Request, principal: _ChatSenderDep, chat_id: UUID) -> Response:
    """Handle DELETE /api/chats/{chat_id} — move a chat of the caller to the trash.

    Sets ``deleted_at`` (the messages stay until the purge, #194) and records
    ``chat.delete`` in the same transaction (a failed audit write is a 500
    with nothing changed). The chat's pending confirmation is dropped.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (needs ``chat.send``).
        chat_id: The chat (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 429 when rate-limited. A chat the caller can't reach is
            the 404 ``chat_not_found``, with nothing changed (another user's
            pending confirmation included).
    """
    _check_rate_limit("/api/chats/delete", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    await chats.trash_chat(
        get_pool(),
        tenant,
        chat_id,
        ip=request.client.host if request.client is not None else None,
    )
    _chat_runtime.pop_pending(chat_id)
    return Response(status_code=204)


def _denied_tool_results(
    history: list[LLMMessage], pending: PendingConfirmation, denied: str
) -> list[LLMMessage]:
    """The ``tool`` results closing the last assistant turn's dangling calls of ``history``.

    One per dangling ``tool_use`` block, in block order (those of
    ``_close_dangling_tool_use``): the pending call's is ``denied`` (a user's
    denial, or the per-user pending limit), any other (a later call of the
    same batch) is cancelled.
    """
    return [
        LLMMessage(role="tool", content=denied, tool_call_id=message.tool_call_id)
        if message.tool_call_id == pending.tool_call.tool_call_id
        else message
        for message in _close_dangling_tool_use(history)[len(history) :]
    ]


@dataclass(frozen=True, slots=True)
class _HeldRun:
    """A chat's run about to start, under the chat's hold.

    What the run's turn is stored against (``_finish_run``) and, for an
    untitled chat's first exchange, the message its automatic title is made
    from. A streamed run's detached task (GH-8) gets it with the hold.
    """

    pool: asyncpg.Pool
    tenant: TenantContext
    # The chat as read under the hold.
    chat: chats.ChatRecord
    # The stored messages the run's history was built from.
    loaded: list[LLMMessage]
    platform: scoped_settings.StoredPlatformSettings
    policy: ToolPolicy
    # The user message of an untitled chat's first exchange (GH-179); None: no title.
    title_message: str | None = None
    # The files the turn's user message sends (GH-187, checked before the hold).
    attachment_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class _StoredRun:
    """A run's turn as ``_finish_run`` stored it: what the JSON answer and the stream report."""

    status: AgentStatus
    response: str
    error_code: Literal[LLMErrorCode, "rate_limit"] | None
    pending: PendingConfirmationSummary | None
    # The turn's last stored message; None when the run added no message.
    message_id: UUID | None


async def _finish_run(run: _HeldRun, result: AgentResult) -> _StoredRun:
    """Store a run's new messages and keep its pending confirmation.

    Called under the chat's lock. The agent returns the history it got
    followed by the run's messages, so the new ones are
    ``result.history[len(run.loaded):]`` (synthetic cancelled results
    included). The last one is stored with the run's status (``final`` as
    ``complete``, GH-8: ``stopped`` as ``stopped``) and its tool calls, in one
    append.

    An ``awaiting_confirmation`` run's confirmation goes to ``_chat_runtime``
    before the append, checked against the caller's pending limit (the stored
    platform ``max_pending_confirmations``: the most the caller may hold in
    their other chats) in the same step (GH-24), and is dropped again when the
    append fails. At the limit nothing is kept: the turn is stored with the
    closing ``tool`` results of the dangling calls (the pending call's
    ``_PENDING_LIMIT_TOOL_RESULT_MSG``, any other the cancelled result) and a
    reply naming the call, the last one with status ``error``, and the run
    reports ``error_code: "rate_limit"``.

    Args:
        run: The held run (the pool, the caller's org scope, the chat, the
            loaded messages and the platform settings read for the request).
        result: The run's result.

    Returns:
        The stored turn: its status, reply, error code (the run's LLM error
        code, or ``rate_limit`` when its confirmation was refused), kept
        confirmation and last message id.

    Raises:
        chats.ChatNotFoundError: The chat was trashed during the run; nothing
            is stored and no confirmation kept.
    """
    chat = run.chat
    new_messages = result.history[len(run.loaded) :]
    status: AgentStatus = result.status
    response = result.response
    error_code: Literal[LLMErrorCode, "rate_limit"] | None = result.error_code
    pending = result.pending_confirmation
    pending_summary: PendingConfirmationSummary | None = None
    if status == "awaiting_confirmation" and pending is not None:
        try:
            # Checks the limit and stores without an await in between, so two concurrent
            # turns of the caller can't both take the last slot.
            _chat_runtime.set_pending(
                chat.id,
                run.tenant.user_id,
                pending,
                max_pending_per_user=run.platform.limits.max_pending_confirmations,
            )
        except PendingConfirmationLimitError:
            # A 200, not a 429: the turn already ran and is stored, and a client
            # retrying a 429 would run it twice. Safe f-string: tool and action are
            # Pydantic-validated identifiers (pattern ^[a-z][a-z0-9_]{0,62}$);
            # ChatResponse.sanitize_response is defence-in-depth.
            response = (
                f"Action {pending.tool_call.tool}.{pending.tool_call.action} was not run:"
                " too many confirmations are pending. Approve or deny one of them first."
            )
            new_messages = [
                *new_messages,
                *_denied_tool_results(result.history, pending, _PENDING_LIMIT_TOOL_RESULT_MSG),
                LLMMessage(role="assistant", content=response),
            ]
            status, error_code = "error", "rate_limit"
            logger.info("Chat %s: confirmation refused, too many pending", safe_log(chat.id))
        else:
            pending_summary = _summarise_pending(pending)
    try:
        message_id = await chats.append_messages(
            run.pool,
            run.tenant,
            chat.id,
            new_messages,
            final_status=_STORED_STATUS[status],
            tool_calls=result.tool_calls,
            # GH-187: linked to the turn's user message in its transaction; none (the
            # default) adds no statement.
            attachment_ids=run.attachment_ids,
        )
    except BaseException:
        # Whatever stopped the store (a chat trashed meanwhile, a database error, a
        # cancelled request), no confirmation may outlive the messages it belongs to.
        if pending_summary is not None:
            _chat_runtime.pop_pending(chat.id)
        raise
    logger.info(
        "Completed message for chat %s: status=%s, tool_calls=%d",
        safe_log(chat.id),
        status,
        len(result.tool_calls),
    )
    return _StoredRun(
        status=status,
        response=response,
        error_code=error_code,
        pending=pending_summary,
        message_id=message_id,
    )


def _chat_response(
    chat_id: UUID, session_id: str | None, result: AgentResult, stored: _StoredRun
) -> ChatResponse:
    """The JSON answer of a stored run (``session_id`` echoes a legacy session id)."""
    return ChatResponse(
        chat_id=chat_id,
        session_id=session_id,
        response=stored.response,
        tool_calls=result.tool_calls,
        status=cast("_JsonStatus", stored.status),
        pending_confirmation=stored.pending,
        error_code=stored.error_code,
    )


def _read_external_content(loaded: list[LLMMessage], result: AgentResult) -> bool:
    """Whether the run's new messages hold wrapped external content (GH-243).

    The same rule as the chat's sticky ``external_content`` flag
    (``chats.append_messages``): only a ``tool`` result counts, so a marker the
    user typed or the reply quotes doesn't.
    """
    return any(
        message.role == "tool" and untrusted.contains_wrapped(message.content)
        for message in result.history[len(loaded) :]
    )


def _running_llm_client() -> LLMClient:
    """The agent's LLM client at the moment of the call (a title task's resolver).

    A title task calls it after the response was sent, so a platform LLM
    switch in between gives the new client. An agent without a client
    raises, which the task turns into the fallback title.

    Raises:
        RuntimeError: No agent is configured.
    """
    if _agent is None:
        raise RuntimeError("Server not configured")
    return _agent._llm


def _title_call(
    run: _HeldRun, result: AgentResult, stored: _StoredRun
) -> Callable[[], Awaitable[None]] | None:
    """The automatic title of an untitled chat's first exchange (GH-179); None for any other run.

    ``chat_titles.title_chat`` with the model's title made from the message
    and the reply, or the fallback from the message. A turn stored as
    ``error`` (a confirmation refused with ``rate_limit`` included) or
    ``stopped`` (GH-8) makes no model call, nor does a run whose new ``tool``
    results hold wrapped external content (``_read_external_content``): the
    reply may quote an email or a file, which must not choose the title. The
    call gets the agent's client when it runs (``_running_llm_client``), the
    org's data residency and the stored ``llm.max_retries``, and holds no chat
    lock: a later turn's history holds the reply, so it titles nothing again.
    """
    if run.title_message is None:
        return None
    return functools.partial(
        chat_titles.title_chat,
        run.pool,
        run.tenant,
        run.chat.id,
        get_client=_running_llm_client,
        user_message=run.title_message,
        assistant_message=result.response,
        run_failed=stored.status in ("error", "stopped"),
        external_content=_read_external_content(run.loaded, result),
        data_residency=run.policy.data_residency,
        max_retries=run.platform.llm.max_retries,
    )


# ---------------------------------------------------------------------------
# Streamed runs (GH-8): the frames, the detached run task
# ---------------------------------------------------------------------------

_INTERNAL_ERROR_PAYLOAD: Final = ErrorPayload(code="internal_error", message=_INTERNAL_ERROR_DETAIL)
_CHAT_GONE_PAYLOAD: Final = ErrorPayload(
    code="chat_not_found", message=_CHAT_NOT_FOUND_BODY["detail"]
)
# The run outcomes whose last answer ended as the model meant it (C11): its last
# word is sent, unless an output cap cut the answer (GH-25: ``result.truncated``).
# Any other end (stopped, error) cuts it, as the stored stopped reply is cut. A
# confirmation refused at the pending limit is stored as error but its run
# (awaiting_confirmation) ended its answer with the gated call.
_COMPLETE_ANSWERS: Final[frozenset[AgentStatus]] = frozenset(
    {"final", "limit_reached", "awaiting_confirmation"}
)
# The OpenAPI 200 of the two streaming routes: the JSON ChatResponse (their
# response_model) or, with ``Accept: text/event-stream``, the run's events.
_EVENT_STREAM_RESPONSES: Final[dict[int | str, dict[str, object]]] = {
    200: {
        "description": (
            "The ChatResponse, or the run's events with Accept: text/event-stream "
            "(run_started, delta, tool_call, confirm, message_saved, error, title, done)."
        ),
        "content": {"text/event-stream": {"schema": {"type": "string"}}},
    }
}


def _wants_event_stream(request: Request) -> bool:
    """Whether a chat request's ``Accept`` header asks for the SSE answer (GH-8)."""
    return event_stream.accepts_event_stream(", ".join(request.headers.getlist("accept")))


class _RunFrames:
    """The SSE frames of one streamed run, queued for its response (GH-8).

    Starts with ``run_started``. ``send`` never waits for the client: the
    response relays the queue, and a gone client leaves the rest unread.
    ``on_delta`` and ``on_tool_call`` are the run's ``RunStream`` sinks: the
    answer text goes through one ``DisplayDeltas``, flushed before every
    ``tool_call`` and when the run ends (``end_answer``), so a ``delta``
    carries display text only and never part of a credential. Neither sink
    nor ``send`` ever raises into the run or waits: a frame that can't be
    built is dropped, so a reporting failure can't lose a turn whose tool
    calls already ran.
    """

    def __init__(self, chat_id: UUID) -> None:
        """Queue ``run_started`` for the chat."""
        self._chat_id = chat_id
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._deltas = DisplayDeltas()
        self.send("run_started", RunStartedPayload(chat_id=chat_id))

    def send(self, event: str, payload: BaseModel) -> None:
        """Queue one frame: ``payload`` as JSON (a non-finite number is null).

        A frame ``SSEEvent`` refuses (over its size cap, say) is dropped: only
        the event name and the exception class are logged, never the payload
        or the exception's text, which may quote it.
        """
        try:
            frame = _make_sse_event(event, payload.model_dump(mode="json"))
        except ValueError as exc:
            # ValueError covers a pydantic ValidationError and a non-finite number.
            logger.warning(
                "Dropped the %s frame of chat %s: %s",
                event,
                safe_log(self._chat_id),
                type(exc).__name__,
            )
            return
        self._queue.put_nowait(frame)

    def text(self, pieces: list[str]) -> None:
        """Queue a ``delta`` per display piece."""
        for piece in pieces:
            self.send("delta", DeltaPayload(text=piece))

    async def on_delta(self, text: str) -> None:
        """Take the run's next raw answer text; send what is settled."""
        self.text(self._deltas.feed(text))

    async def on_tool_call(self, record: ToolCallRecord) -> None:
        """Send the answer so far, then the recorded dispatch's ``tool_call``.

        The answer before a tool call is complete: its last word is sent.
        """
        self.end_answer(complete=True)
        self.send("tool_call", record)

    def end_answer(self, *, complete: bool) -> None:
        """Send what is held of the current answer.

        ``complete=False`` (the answer was cut: a stop, an error) drops its
        unfinished last word, so a key cut short is never shown in part.
        """
        self.text(self._deltas.flush(complete=complete))

    def end(self) -> None:
        """Queue ``done``, the last frame."""
        self.send("done", DonePayload())
        self._queue.put_nowait(None)

    async def relay(self) -> AsyncIterator[str]:
        """The queued frames in order, up to ``done``."""
        while (frame := await self._queue.get()) is not None:
            yield frame


def _report_stored(frames: _RunFrames, stored: _StoredRun) -> None:
    """Send how a stored run ended: the frames after its deltas and tool calls (C5.3)."""
    if stored.status == "limit_reached":
        # The agent adds the limit notice without streaming it.
        frames.text(display_pieces(stored.response))
    if stored.pending is not None:
        frames.send("confirm", stored.pending)
    if stored.message_id is not None:
        frames.send(
            "message_saved",
            MessageSavedPayload(message_id=stored.message_id, status=_STORED_STATUS[stored.status]),
        )
    if stored.status == "error":
        frames.send(
            "error",
            ErrorPayload(code=stored.error_code or "internal_error", message=stored.response),
        )


async def _send_title(
    frames: _RunFrames, run: _HeldRun, result: AgentResult, stored: _StoredRun
) -> None:
    """Title an untitled chat's first streamed exchange, then send the stored title (C5.6).

    The chat is read after ``_title_call``'s call: a ``title`` frame only for
    an automatic title that is stored (a rename during the run wins and sends
    none; a chat trashed meanwhile sends none).
    """
    title = _title_call(run, result, stored)
    if title is None:
        return
    await title()
    try:
        chat = await chats.get_chat(run.pool, run.tenant, run.chat.id)
    except chats.ChatNotFoundError:
        return
    if chat.title_source == "auto" and chat.title:
        frames.send("title", TitlePayload(title=chat.title))


async def _streamed_run(
    held: contextlib.AsyncExitStack,
    run: _HeldRun,
    start: Callable[..., Awaitable[AgentResult]],
    stream: RunStream,
    frames: _RunFrames,
) -> None:
    """A streamed run's detached task: run and store the turn, free the chat, then report it.

    ``held`` is the chat's hold and the run's stop registration the route
    took; they go once the turn is stored and before ``confirm``,
    ``message_saved`` or ``error`` is sent, so a client may send the next
    message or confirm as soon as it sees them. An agent that raised is
    ``error{internal_error}`` and a chat trashed during the run
    ``error{chat_not_found}``, both with nothing stored (the JSON route's 500
    and 404). A stored turn is reported, then an untitled chat's first exchange
    is titled (``_send_title``). ``done`` always ends the stream. Nothing here
    waits for the client, so a turn whose client left is still stored and
    titled. Log lines name the chat id and an exception class only.

    The answer's held text is sent once the outcome is known (a trashed chat
    only shows when the store raises): whole for a stored ``final``,
    ``limit_reached`` or ``awaiting_confirmation`` run, without its
    unfinished last word for any other end and for a ``truncated`` final
    answer (C11, GH-25: a key the stop, error or output cap cut short is
    never shown in part).
    """
    chat_id = run.chat.id
    try:
        result: AgentResult | None = None
        stored: _StoredRun | None = None
        async with held:
            try:
                result = await start(stream=stream)
            except Exception:
                # Nothing is stored, like the JSON route's 500; the deltas sent stay sent.
                logger.error("Agent run failed for chat %s", safe_log(chat_id))
            if result is not None:
                with contextlib.suppress(chats.ChatNotFoundError):
                    stored = await _finish_run(run, result)
            frames.end_answer(
                complete=stored is not None
                and result is not None
                and result.status in _COMPLETE_ANSWERS
                # GH-25 (D7): a final answer an output cap cut is stored without
                # its unfinished last word, so the stream drops it as well.
                and not result.truncated
            )
        if result is None:
            frames.send("error", _INTERNAL_ERROR_PAYLOAD)
        elif stored is None:
            frames.send("error", _CHAT_GONE_PAYLOAD)
        else:
            _report_stored(frames, stored)
            # The turn's timing line ends here: the title call isn't part of the turn.
            request_timing.finish()
            await _send_title(frames, run, result, stored)
    except Exception as exc:
        # A failed store (other than a trashed chat) or title read: the JSON route's 500.
        logger.error("Streamed run failed for chat %s: %s", safe_log(chat_id), type(exc).__name__)
        frames.send("error", _INTERNAL_ERROR_PAYLOAD)
    finally:
        # Every other ending writes the line here (finish() writes it only once).
        request_timing.finish()
        frames.end()


def _start_stream(
    held: contextlib.AsyncExitStack,
    run: _HeldRun,
    start: Callable[..., Awaitable[AgentResult]],
) -> EventStreamResponse:
    """Hand a held run to a detached task and answer with its event stream (GH-8).

    Called under the chat's hold (``held``). The run's stop signal is
    registered there (``ChatRuntime.stoppable``, read at request time), so
    ``POST /api/chats/{id}/stop`` reaches it, and the task takes the hold and
    the registration over (``_streamed_run``). The client leaving sets the
    same signal (``EventStreamResponse``).

    The response ends before the run does, so the request's timing line is
    detached from it (``request_timing.detach``): the task, which shares the
    request's timing record, writes it once the turn is stored and reported.
    """
    stop = held.enter_context(_chat_runtime.stoppable(run.chat.id))
    frames = _RunFrames(run.chat.id)
    stream = RunStream(on_delta=frames.on_delta, on_tool_call=frames.on_tool_call, stop=stop)
    event_stream.detach(_streamed_run(held.pop_all(), run, start, stream, frames), stop=stop)
    # Only once the task holds the run: a failure before that is still the request's line.
    request_timing.detach()
    return EventStreamResponse(frames.relay(), stop=stop)


async def _chat_turn(
    principal: Principal,
    message: str,
    chat_ref: UUID | str,
    background_tasks: BackgroundTasks,
    *,
    attachment_ids: Sequence[UUID] = (),
    streamed: bool = False,
) -> ChatResponse | EventStreamResponse:
    """Run one user message in a chat and store the turn (the two turn routes).

    The caller spent the ``/api/message`` bucket. Expired confirmations are
    reaped and the org's due critical permission promotions completed first
    (in memory: a statement only for a due one). The message length and the
    run's limits are the stored platform limits, and its LLM retry limit the
    stored ``llm.max_retries`` (GH-242), read on every request through the
    settings cache (GH-160: a change applies without a restart); so are the
    org's tool policy (GH-161, the org's data residency included) and the
    caller's prompt context (GH-170: the org's instructions and default
    response language, the user's response language, timezone and personal
    instructions). A failing load escapes before the run: the generic 500,
    nothing of it echoed or logged.

    GH-244: a chat id's turn makes at most 3 statements before its LLM call
    (the steady state: no session touch due, the settings cache warm, no due
    promotion): the session lookup, the turn setup
    (``turn_setup.load_turn_setup``: the policy, the prompt context and the
    owner check, a chat the caller can't reach being the 404 before the
    hold) and, under the hold, the chat with its latest messages
    (``chats.load_turn``).

    GH-187: a message with files has them checked right after the owner check
    (``attachments.check_sendable``, one statement; none without files), before
    the hold and the run, and the stored turn links them to its user message
    (``_finish_run``).

    A legacy session id keeps its separate reads before the hold
    (``org_permissions.load_tool_policy``,
    ``scoped_settings.load_prompt_context``, ``chats.find_legacy_chat``;
    until #177). A session without a chat gets a server-generated id (uuid4)
    and its chat is created only once that id's runtime entry is held
    (``chats.get_or_create_legacy_chat``, GH-266): a 429 ``rate_limit`` or a
    503 ``chats_busy`` writes nothing. When a concurrent first message of
    the same session created the chat meanwhile, the turn runs in that chat,
    under that chat's hold too, so the session keeps one chat.

    GH-8: the chat is taken with ``hold(wait=False)``: while a run of the chat
    is going (a message, an approved confirmation, a denial being stored) the
    message is refused at once (``ChatRunActiveError``, the 409
    ``run_active``), with nothing run or stored and the chat's pending
    confirmation untouched. Under the hold the chat and its latest
    ``max_context_messages`` messages are read (``chats.load_turn``: a chat
    trashed meanwhile is the 404), a pending confirmation of the chat is
    cancelled (a message instead of a confirmation), a dangling ``tool_use``
    gets its synthetic cancelled result, and the agent runs with
    ``str(chat.id)`` as its session id and the chat's sticky
    ``external_content`` flag (GH-243) as read under the hold. Then the turn
    is stored (``_finish_run``: a confirmation it asks for is kept within the
    caller's stored ``max_pending_confirmations``, else refused with
    ``rate_limit``, GH-24).

    A JSON turn runs here and its chat's first exchange (the chat as read
    under the hold is untitled with ``title_source`` "auto", and the loaded
    history holds no ``assistant`` message; a GH-66 notice is a user message)
    is titled after the response is sent (``_title_call``, a background
    task). A streamed turn (GH-8) runs in a detached task that stores it,
    frees the chat, reports it and titles a first exchange before ``done``
    (``_start_stream``). A chat trashed during the run titles nothing. Either
    way the title call comes after the request's timing line (GH-244) and
    never counts in it.

    Args:
        principal: The logged-in principal (``chat.send`` checked).
        message: The validated user message.
        chat_ref: The chat's id, or a legacy session id (the caller's chat of
            it, created by its first run, until #177).
        background_tasks: The request's background tasks (a JSON turn's title).
        attachment_ids: The files the message sends (a chat id's turn only;
            their number already checked against the platform limit).
        streamed: Answer with the run's event stream (the chat route with
            ``Accept: text/event-stream``) instead of the JSON ChatResponse.

    Returns:
        The turn's ChatResponse (``session_id`` echoes a legacy session id),
        or the streamed turn's EventStreamResponse.

    Raises:
        HTTPException: 422 over the stored message length; 500 when the agent
            of a JSON turn fails (nothing stored).
        chats.ChatNotFoundError: The chat isn't the caller's, or was trashed
            during a JSON turn's run (404 ``chat_not_found``, nothing stored).
        attachments.AttachmentNotFoundError: A file isn't the caller's live
            one of the chat (404 ``attachment_not_found``; no run).
        attachments.AttachmentAlreadySentError: A file was already sent (409
            ``attachment_already_sent``; no run).
        ChatRunActiveError: A run of the chat is going (409 ``run_active``,
            GH-8; no run, nothing stored).
        ChatRuntimeUserLimitError: The chat has no runtime entry and the
            caller's entries are all in use or hold a pending confirmation
            (429 ``rate_limit``, GH-24; no run, nothing stored, no chat
            created).
        ChatRuntimeFullError: The runtime is full and no entry can be evicted
            (503 ``chats_busy``, no run, no chat created).
    """
    if _agent is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _reap_expired_confirmations()

    from admino.database import get_pool

    pool = get_pool()
    await _resolve_due_promotions(pool, principal)

    # Enforce the stored max_message_length (tighter than Pydantic's 32768).
    platform = await _platform_run_settings()
    max_len = platform.limits.max_message_length
    if len(message) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"Message exceeds maximum length of {max_len} characters",
        )
    tenant = TenantContext.from_principal(principal)

    session_id: str | None = None
    # A legacy session id without a chat yet: its chat is created under the hold.
    new_session: str | None = None
    # Resolves the chat (the 404) before the hold; it is read again under the hold.
    if isinstance(chat_ref, UUID):
        # One statement for the policy, the prompt context and the owner check: a send
        # makes at most 3 statements before its LLM call (GH-244).
        setup = await turn_setup.load_turn_setup(pool, tenant, chat_ref)
        if not setup.chat_found:
            raise chats.ChatNotFoundError
        await attachments.check_sendable(pool, tenant, chat_ref, attachment_ids)
        policy = setup.policy
        prompt_context = setup.prompt_context
        chat_id = chat_ref
    else:
        # The legacy route keeps its separate reads until it is retired (#177).
        policy = await org_permissions.load_tool_policy(pool, tenant)
        prompt_context = await scoped_settings.load_prompt_context(pool, tenant)
        session_id = chat_ref
        try:
            chat_id = (await chats.find_legacy_chat(pool, tenant, chat_ref)).id
        except chats.ChatNotFoundError:
            # Nothing is written before the runtime entry is held: a refused hold (429
            # rate_limit, 503 chats_busy) leaves no empty chat behind (GH-266).
            chat_id, new_session = uuid4(), chat_ref

    # One run per chat at a time (GH-8): a busy chat refuses the message, so each run
    # loads what the previous one stored.
    async with contextlib.AsyncExitStack() as held:
        await held.enter_async_context(_chat_runtime.hold(chat_id, tenant.user_id, wait=False))
        if new_session is not None:
            created = await chats.get_or_create_legacy_chat(
                pool, tenant, new_session, chat_id=chat_id
            )
            if created.id != chat_id:
                # A concurrent first message of the session created its chat meanwhile:
                # run there under that chat's hold too (busy: the 409). Only for another
                # id: hold isn't reentrant, and the provisional entry stays an idle
                # lock-only one.
                chat_id = created.id
                await held.enter_async_context(
                    _chat_runtime.hold(chat_id, tenant.user_id, wait=False)
                )
        # The chat and its latest messages, read under the hold in one statement: a chat
        # trashed meanwhile is the 404, and an approval that ran in front may have set
        # external_content (GH-243), which must escalate this run (audit M-1).
        turn = await chats.load_turn(
            pool, tenant, chat_id, limit=platform.limits.max_context_messages
        )
        chat, loaded = turn.chat, turn.history
        if _chat_runtime.pop_pending(chat.id) is not None:
            logger.info(
                "Chat %s got a new message while a confirmation was pending: cancelled",
                safe_log(chat.id),
            )
        logger.info("Processing message for chat %s", safe_log(chat.id))
        # Only an untitled chat's first exchange is titled: a stored reply means it had
        # one (a GH-66 notice is a user message and doesn't count).
        first_exchange = (
            chat.title_source == "auto"
            and chat.title == ""
            and not any(stored.role == "assistant" for stored in loaded)
        )
        run = _HeldRun(
            pool=pool,
            tenant=tenant,
            chat=chat,
            loaded=loaded,
            platform=platform,
            policy=policy,
            title_message=message if first_exchange else None,
            attachment_ids=tuple(attachment_ids),
        )
        start = functools.partial(
            _agent.run,
            user_message=message,
            session_id=str(chat.id),
            history=_close_dangling_tool_use(loaded),
            principal=principal,
            tool_policy=policy,
            agent_config=_run_config(platform),
            prompt_context=prompt_context,
            earlier_external_content=chat.external_content,
        )
        if streamed:
            return _start_stream(held, run, start)
        try:
            result = await start()
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent run failed for chat %s", safe_log(chat.id))
            raise HTTPException(status_code=500, detail="Internal error") from None
        stored = await _finish_run(run, result)
    # Runs after the response, without the chat's hold.
    title = _title_call(run, result, stored)
    if title is not None:
        background_tasks.add_task(title)
    return _chat_response(chat.id, session_id, result, stored)


async def post_chat_message(
    request: Request,
    principal: _ChatSenderDep,
    chat_id: UUID,
    body: ChatMessageCreate,
    background_tasks: BackgroundTasks,
) -> ChatResponse | EventStreamResponse | JSONResponse:
    """Handle POST /api/chats/{chat_id}/messages — run a turn in a chat of the caller.

    Spends the per-user ``/api/message`` bucket (shared with the legacy
    route), then runs and stores the turn (``_chat_turn``). GH-8: with an
    ``Accept`` header listing ``text/event-stream`` (q above 0) the answer is
    the run's event stream; every refusal before the run is the same JSON
    error either way. A JSON turn's first exchange titles an untitled chat
    after the response is sent (GH-179); a streamed one before ``done``.

    GH-187: ``attachment_ids`` above the stored platform
    ``max_files_per_message`` (read on every request) are the 422
    ``too_many_files``, before any attachment statement; the files are then
    checked after the chat's owner check and linked to the stored user
    message. A message without files makes the statements it made before.

    Args:
        request: The incoming request (its ``Accept`` header).
        principal: The logged-in principal (needs ``chat.send``).
        chat_id: The chat (a UUID; anything else is a 422).
        body: Validated ChatMessageCreate (the message and the files it sends).
        background_tasks: The request's background tasks (the title task).

    Returns:
        ChatResponse with the chat's id (``session_id`` None), the agent's
        reply, the tool call summary, the pending confirmation and the error
        code: the run's LLM error code, or ``rate_limit`` (``status:
        "error"``, GH-24) when the caller already holds the stored
        ``max_pending_confirmations`` in other chats; None otherwise. Or the
        streamed run's EventStreamResponse. Or the 422 ``too_many_files``.

    Raises:
        HTTPException: 429 when rate-limited, 422 over the stored message
            length, 500 when a JSON turn's agent fails. A chat the caller
            can't reach is the 404 ``chat_not_found``; a file that isn't the
            caller's live one of the chat the 404 ``attachment_not_found``
            and a file already sent the 409 ``attachment_already_sent``
            (GH-187); a chat whose run is going the 409 ``run_active``
            (GH-8); the caller at their chat-runtime bound the 429
            ``rate_limit`` (GH-24); a full chat runtime with nothing to evict
            the 503 ``chats_busy``.
    """
    _check_rate_limit("/api/message", _user_caller(principal))
    # Only a message with files reads the limit here (from the settings cache), so a
    # message without makes the statements it made before (GH-244).
    if body.attachment_ids:
        files = (await _platform_run_settings()).files
        if len(body.attachment_ids) > files.max_files_per_message:
            return JSONResponse(status_code=422, content=_TOO_MANY_FILES_BODY)
    return await _chat_turn(
        principal,
        body.message,
        chat_id,
        background_tasks,
        attachment_ids=body.attachment_ids,
        streamed=_wants_event_stream(request),
    )


async def post_message(
    body: ChatRequest,
    principal: _ChatSenderDep,
    background_tasks: BackgroundTasks,
) -> ChatResponse | EventStreamResponse:
    """Handle POST /api/message — legacy: a turn in the caller's chat of a session id.

    The session id names the caller's own persisted chat
    (``chats.legacy_session_id``), created once its first message can run
    (a refused one creates none, GH-266): another user's session id is a
    chat of the caller's own. The turn then runs like
    POST /api/chats/{chat_id}/messages (``_chat_turn``), on the same per-user
    ``/api/message`` bucket, and titles the chat after its first exchange
    the same way (GH-179). Always JSON, whatever the ``Accept`` header
    (GH-8). Until #177.

    Args:
        body: Validated ChatRequest with message and session_id.
        principal: The logged-in principal (needs ``chat.send``).
        background_tasks: The request's background tasks (the title task).

    Returns:
        ChatResponse with the chat's id, the echoed session id, the agent's
        reply, the tool call summary, the pending confirmation and the error
        code: the run's LLM error code, or ``rate_limit`` (``status:
        "error"``, GH-24) when the caller already holds the stored
        ``max_pending_confirmations`` in other chats; None otherwise.

    Raises:
        HTTPException: 429 when rate-limited, 422 over the stored message
            length, 500 when the agent fails. A chat whose run is going is
            the 409 ``run_active`` (GH-8); the caller at their chat-runtime
            bound the 429 ``rate_limit`` (GH-24); a full chat runtime with
            nothing to evict the 503 ``chats_busy``.
    """
    _check_rate_limit("/api/message", _user_caller(principal))
    return await _chat_turn(principal, body.message, body.session_id, background_tasks)


async def post_chat_stop(principal: _ChatSenderDep, chat_id: UUID) -> ChatStopResponse:
    """Handle POST /api/chats/{chat_id}/stop — stop a chat's streamed run (GH-8).

    Spends the per-user ``/api/chats/stop`` bucket, then reads the chat with
    the caller's tenant (the owner check) and sets its streamed run's stop
    signal (``ChatRuntime.request_stop``: never creates a runtime entry, never
    waits). The run then ends as the agent's stop allows (a running tool call
    finishes and is recorded) and is stored ``stopped``; its stream reports
    it. No request body is read; no audit event (sending isn't one either).

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        chat_id: The chat (a UUID; anything else is a 422).

    Returns:
        ``{"stopped": true}`` when a streamed run of the chat was stopped;
        ``{"stopped": false}`` when the chat has none (nothing running, or a
        JSON request's run, which can't be stopped).

    Raises:
        HTTPException: 429 when rate-limited. Another org's, a colleague's,
            a trashed and an unknown chat are the 404 ``chat_not_found``.
    """
    _check_rate_limit("/api/chats/stop", _user_caller(principal))

    from admino.database import get_pool

    chat = await chats.get_chat(get_pool(), TenantContext.from_principal(principal), chat_id)
    stopped = _chat_runtime.request_stop(chat.id)
    if stopped:
        logger.info("Stop requested for chat %s", safe_log(chat.id))
    return ChatStopResponse(stopped=stopped)


async def post_confirm(
    request: Request,
    principal: _ChatSenderDep,
    confirmation_id: str = Path(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Confirmation identifier. Alphanumeric, hyphens, underscores only.",
    ),
    body: ConfirmRequest = ...,  # type: ignore[assignment]
) -> ChatResponse | EventStreamResponse:
    """Handle POST /api/confirm/{confirmation_id} — approve or deny a pending action.

    The body names the chat by ``chat_id`` or by the legacy ``session_id``
    (looked up, never created); a chat the caller can't reach, or one
    without a pending confirmation in ``_chat_runtime``, is the same 404.
    A confirm never creates a runtime entry: a chat without one is that 404
    before its hold is taken, so nothing is evicted, run or stored (GH-24).
    Expired confirmations are reaped first. A confirmation waits for a run of
    its chat that is going (``hold()``: that run may store the confirmation
    being approved). Under the chat's hold the confirmation id and the expiry
    are checked (``_utc_now``) and the confirmation is consumed: one that
    expired meanwhile (while the request waited for the hold) is popped and
    answers the same 404 as one already reaped, with nothing run or stored
    (GH-24). A denial stores the closing ``tool`` results (the denied call's
    "Tool call denied by the user.", any other dangling call's cancelled
    result) and the assistant's denial, so the history stays well-formed. An
    approval resumes the agent on the latest ``max_context_messages`` stored
    messages (the dangling ``tool_use`` left as it is: the resume dispatches
    it), with the caller's principal, the chat's ``external_content`` flag
    (read again under the hold, so a turn that ran in front of the approval
    counts), the stored platform limits and LLM retry limit (read on every
    request, GH-160, GH-242) and their org's tool policy as it is now (loaded
    again, after completing the org's due promotions; GH-161), then stores the
    run like a turn (a confirmation it asks for counts against the caller's
    stored ``max_pending_confirmations`` in their other chats, the consumed
    one not included; GH-24). An approved resume also loads the caller's
    prompt context again (GH-170), so a change made while the confirmation
    was pending applies; a failing load is the generic 500 with nothing
    resumed, echoed or logged. Under the org's data residency a resumed run
    whose LLM provider has meanwhile become non-Swiss ends with
    ``residency_blocked`` before the approved tool is dispatched (the agent's
    guard). Another user's pending confirmation is never found (404).

    GH-8: with an ``Accept`` header listing ``text/event-stream`` an approval
    streams the resumed run like a turn (no title), and a denial streams
    ``run_started``, the denial as a ``delta``, ``message_saved`` and ``done``
    once it is stored and the chat is free; every refusal is the JSON error.

    Args:
        request: The incoming request (its ``Accept`` header).
        principal: The logged-in principal (needs ``chat.send``).
        confirmation_id: The confirmation ID from the URL path (Pydantic-validated).
        body: Validated ConfirmRequest with ``chat_id`` or ``session_id``, the
            confirmation id and the approved flag.

    Returns:
        ChatResponse naming the chat (``session_id`` echoed when given) with
        the result of the resumed agent run (its LLM error code, or
        ``rate_limit`` when the confirmation it asked for was refused; None
        for a denial); or the streamed EventStreamResponse.

    Raises:
        HTTPException: 404 if no confirmation is pending for the chat, it has
            expired or the id doesn't match, 400 if the IDs mismatch, 500
            when a JSON approval's agent fails. A chat trashed meanwhile is
            the 404 ``chat_not_found``.
    """
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/confirm", _user_caller(principal))
    _reap_expired_confirmations()

    from admino.database import get_pool

    pool = get_pool()
    await _resolve_due_promotions(pool, principal)
    platform = await _platform_run_settings()
    tenant = TenantContext.from_principal(principal)
    policy = await org_permissions.load_tool_policy(pool, tenant)

    try:
        if body.chat_id is not None:
            chat = await chats.get_chat(pool, tenant, body.chat_id)
        else:
            # ConfirmRequest names exactly one of chat_id and session_id.
            chat = await chats.find_legacy_chat(pool, tenant, cast("str", body.session_id))
    except chats.ChatNotFoundError:
        raise HTTPException(status_code=404, detail=_NO_PENDING_DETAIL) from None

    # A chat without a runtime entry has nothing pending, and a confirm never creates
    # one: otherwise a stale confirm could hit the per-user 429 or, at capacity, evict
    # the caller's own pending confirmation elsewhere (GH-24, audit L-1). Only "no
    # entry" answers here: an approval queued behind a running turn of the chat must
    # still wait for the hold (the turn may store the confirmation it approves). No
    # await before hold(), so the entry checked is the one hold() finds.
    if chat.id not in _chat_runtime:
        raise HTTPException(status_code=404, detail=_NO_PENDING_DETAIL)

    streamed = _wants_event_stream(request)
    # The chat's hold serialises with its runs; a streamed approval's task takes it over.
    async with contextlib.AsyncExitStack() as held:
        await held.enter_async_context(_chat_runtime.hold(chat.id, tenant.user_id))
        pending = _chat_runtime.get_pending(chat.id)

        if pending is None:
            raise HTTPException(status_code=404, detail=_NO_PENDING_DETAIL)

        if pending.confirmation_id != confirmation_id:
            raise HTTPException(status_code=404, detail="Confirmation not found")

        # Confirmation ID from body must also match (defence-in-depth).
        if body.confirmation_id != confirmation_id:
            raise HTTPException(status_code=400, detail="Confirmation ID mismatch")

        # It may have expired while this request waited for the hold (after its reap
        # kept it): the same 404 as one already reaped, nothing run or stored (GH-24).
        if _utc_now() >= pending.expires_at:
            _chat_runtime.pop_pending(chat.id)
            raise HTTPException(status_code=404, detail=_NO_PENDING_DETAIL)

        # Consume the pending confirmation regardless of approval/denial.
        _chat_runtime.pop_pending(chat.id)
        loaded = await chats.load_recent_history(
            pool, tenant, chat.id, limit=platform.limits.max_context_messages
        )

        if not body.approved:
            logger.info("Confirmation denied for chat %s", safe_log(chat.id))
            # Safe f-string: tool and action are Pydantic-validated with
            # pattern=r"^[a-z][a-z0-9_]{0,62}$", restricting to alphanumeric/
            # underscore. ChatResponse.sanitize_response provides defence-in-depth.
            denial = f"Action {pending.tool_call.tool}.{pending.tool_call.action} was denied."
            message_id = await chats.append_messages(
                pool,
                tenant,
                chat.id,
                [
                    *_denied_tool_results(loaded, pending, _DENIED_TOOL_RESULT_MSG),
                    LLMMessage(role="assistant", content=denial),
                ],
            )
            if streamed:
                # Sent once the handler returned: the chat is free by then.
                frames = _RunFrames(chat.id)
                frames.text(display_pieces(denial))
                _report_stored(
                    frames,
                    _StoredRun(
                        status="final",
                        response=denial,
                        error_code=None,
                        pending=None,
                        message_id=message_id,
                    ),
                )
                frames.end()
                return EventStreamResponse(frames.relay(), stop=None)
            return ChatResponse(
                chat_id=chat.id,
                session_id=body.session_id,
                response=denial,
                tool_calls=[],
                status="final",
                pending_confirmation=None,
            )

        # Approved — resume the agent with the pending confirmation, the chat's
        # external_content flag as read under the hold (a turn that ran ahead may have
        # set it; security audit M-1) and the prompt context as it is now (GH-170: a
        # change made while the confirmation was pending applies to the resumed run).
        chat = await chats.get_chat(pool, tenant, chat.id)
        prompt_context = await scoped_settings.load_prompt_context(pool, tenant)

        logger.info("Resuming agent for chat %s after a confirmation", safe_log(chat.id))

        run = _HeldRun(
            pool=pool, tenant=tenant, chat=chat, loaded=loaded, platform=platform, policy=policy
        )
        start = functools.partial(
            _agent.run,
            user_message="",
            session_id=str(chat.id),
            history=loaded,
            principal=principal,
            tool_policy=policy,
            pending_confirmation=pending,
            agent_config=_run_config(platform),
            prompt_context=prompt_context,
            earlier_external_content=chat.external_content,
        )
        if streamed:
            return _start_stream(held, run, start)
        try:
            result = await start()
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent resume failed for chat %s", safe_log(chat.id))
            raise HTTPException(status_code=500, detail="Internal error") from None
        stored = await _finish_run(run, result)
    return _chat_response(chat.id, body.session_id, result, stored)


# ---------------------------------------------------------------------------
# Attachments (GH-187): the upload, the metadata and the download
# ---------------------------------------------------------------------------

_UPLOAD_RATE_ROUTE: Final = "/api/chats/attachments/create"
# The platform's max_file_size_mb counts MiB.
_MIB: Final = 1_048_576
# A usable Content-Length: 1 to 18 ASCII digits (no sign, space or other digit; more
# digits are far past every size limit).
_CONTENT_LENGTH_RE: Final = re.compile(r"[0-9]{1,18}")
# The status of each upload refusal; its body is the reason's fixed text and code.
_REFUSAL_STATUS: Final[dict[RefusalReason, int]] = {
    "invalid_filename": 400,
    "content_length_required": 411,
    "empty_file": 400,
    "content_length_mismatch": 400,
    "file_too_large": 413,
    "storage_quota_exceeded": 413,
    "unsupported_type": 415,
    "legacy_office": 415,
    "password_protected": 422,
    "corrupted_file": 422,
    "storage_unavailable": 503,
}


def _attachment_refusal(reason: RefusalReason) -> JSONResponse:
    """An upload's refusal: its status and ``{"detail", "reason"}`` (fixed text, never input)."""
    return JSONResponse(
        status_code=_REFUSAL_STATUS[reason],
        content={"detail": attachment_types.REFUSAL_DETAILS[reason], "reason": reason},
    )


def _declared_length(value: str | None) -> int:
    """The upload's ``Content-Length`` header as a number.

    Raises:
        AttachmentRefusedError: ``content_length_required`` without the
            header, or unless it is 1 to 18 ASCII digits.
    """
    if value is None or _CONTENT_LENGTH_RE.fullmatch(value) is None:
        raise AttachmentRefusedError("content_length_required")
    return int(value)


def _attachment_summary(record: attachments.AttachmentRecord) -> AttachmentSummary:
    """The API summary of a stored attachment: metadata only, never its org, owner or path."""
    return AttachmentSummary.model_validate(record, from_attributes=True)


async def post_chat_attachment(
    request: Request, principal: _FileUploaderDep, chat_id: UUID
) -> AttachmentSummary | JSONResponse:
    """Handle POST /api/chats/{chat_id}/attachments — store one file in a chat of the caller.

    The request body is the file itself, read with ``request.stream()`` only
    once every check that needs none of it passed, in this order: the
    per-user bucket (its burst is the stored platform
    ``max_files_per_message`` when the caller's bucket is created, then one
    every 2 seconds), the name (the percent-encoded ``X-Attachment-Name``
    header, ``attachment_types.sanitize_filename``), the ``Content-Length``
    (required: it bounds the stream), then in
    ``attachments.upload_attachment`` the size against the stored platform
    ``max_file_size_mb`` (MiB, read on every request), the chat's owner and
    the org's storage quota. The declared ``Content-Type`` is ignored: the
    kind comes from the content. A stored file is submitted once to
    ``_processing`` (looked up now) and logged by its ids, size and kind.

    Args:
        request: The incoming request (the name and length headers, the
            body, the client IP for the audit event).
        principal: The logged-in principal (needs ``file.upload``).
        chat_id: The chat (a UUID; anything else is a 422).

    Returns:
        201 with the stored attachment's AttachmentSummary (status
        ``uploaded``). Or a refusal ``{"detail", "reason"}`` with nothing
        stored: 400 ``invalid_filename``, ``empty_file`` or
        ``content_length_mismatch`` (also when the client leaves mid-body),
        411 ``content_length_required``, 413 ``file_too_large`` or
        ``storage_quota_exceeded``, 415 ``unsupported_type`` or
        ``legacy_office``, 422 ``password_protected`` or ``corrupted_file``,
        503 ``storage_unavailable``.

    Raises:
        HTTPException: 429 when rate-limited. A chat the caller can't reach
            (before the body is read, or trashed while it streamed) is the
            404 ``chat_not_found`` (``chats.ChatNotFoundError``).
    """
    from admino.database import get_pool

    pool = get_pool()
    files = (await scoped_settings.current_platform_settings(pool)).files
    _check_rate_limit(
        _UPLOAD_RATE_ROUTE, _user_caller(principal), burst=files.max_files_per_message
    )
    tenant = TenantContext.from_principal(principal)
    root = attachments.attachments_root()
    try:
        filename = attachment_types.sanitize_filename(request.headers.get("x-attachment-name"))
        declared_length = _declared_length(request.headers.get("content-length"))
        record = await attachments.upload_attachment(
            pool,
            tenant,
            chat_id,
            filename=filename,
            declared_length=declared_length,
            body=request.stream(),
            root=root,
            max_bytes=files.max_file_size_mb * _MIB,
            ip=request.client.host if request.client is not None else None,
        )
    except AttachmentRefusedError as exc:
        return _attachment_refusal(exc.reason)
    except ClientDisconnect:
        # The client left mid-body: nothing is stored, and no one reads this answer.
        return _attachment_refusal("content_length_mismatch")
    _processing.submit(pool, root, record.id, tenant.org_id)
    logger.info(
        "Attachment %s stored in chat %s: %d bytes, %s",
        safe_log(record.id),
        safe_log(record.chat_id),
        record.size_bytes,
        record.kind,
    )
    return _attachment_summary(record)


async def get_attachment_metadata(
    principal: _ChatSenderDep, attachment_id: UUID
) -> AttachmentSummary:
    """Handle GET /api/attachments/{attachment_id} — an attachment of the caller.

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        attachment_id: The attachment (a UUID; anything else is a 422).

    Returns:
        The attachment's AttachmentSummary: its metadata and processing
        status (any status), never its bytes.

    Raises:
        HTTPException: 429 when rate-limited. Anything but the caller's own
            live attachment (another org's, a colleague's, a trashed or an
            unknown one) is the 404 ``attachment_not_found``.
    """
    _check_rate_limit("/api/attachments/get", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    return _attachment_summary(await attachments.get_attachment(get_pool(), tenant, attachment_id))


async def get_attachment_content(principal: _ChatSenderDep, attachment_id: UUID) -> FileResponse:
    """Handle GET /api/attachments/{attachment_id}/content — download an attachment of the caller.

    Any status downloads (the stored original, not a processed artifact).

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        attachment_id: The attachment (a UUID; anything else is a 422).

    Returns:
        The stored bytes with the kind's ``Content-Type``, ``Content-Disposition:
        attachment`` naming the percent-encoded download name (the kind's
        extension added when the stored name's doesn't fit, so a ``.html``
        name never downloads as HTML) and ``Cache-Control: no-store``.

    Raises:
        HTTPException: 429 when rate-limited. Anything but the caller's own
            live attachment, and a row whose file is gone, is the 404
            ``attachment_not_found``.
    """
    _check_rate_limit("/api/attachments/content/get", _user_caller(principal))

    from admino.database import get_pool

    tenant = TenantContext.from_principal(principal)
    record = await attachments.get_attachment(get_pool(), tenant, attachment_id)
    path = attachments.attachment_path(attachments.attachments_root(), tenant.org_id, record.id)
    try:
        file_stat = await asyncio.to_thread(path.stat)
    except FileNotFoundError:
        raise attachments.AttachmentNotFoundError from None
    if not stat.S_ISREG(file_stat.st_mode):
        raise attachments.AttachmentNotFoundError
    return FileResponse(
        path,
        stat_result=file_stat,
        media_type=attachment_types.MEDIA_TYPES[record.kind],
        headers={
            "Content-Disposition": attachment_types.content_disposition(
                attachment_types.download_name(record.filename, record.kind)
            ),
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Settings scope route handlers (GH-159): /api/me, /api/org, /api/platform
# ---------------------------------------------------------------------------


def _require_capability(principal: Principal, capability: Capability) -> None:
    """Raise 403 ``Forbidden`` unless the principal has the capability (before any work)."""
    if not can(principal, capability):
        raise HTTPException(status_code=403, detail="Forbidden")


async def _platform_settings_response(
    pool: sessions.Executor, stored: scoped_settings.StoredPlatformSettings
) -> PlatformSettingsResponse:
    """Build the PlatformSettingsResponse of the stored platform row.

    A model that isn't set (NULL) is shown as ``""``. The available models come
    from the two provider probes (filtered again by ``SettingsLLM``); the key
    flags are the presence of the env vars, never their values. The model
    capabilities and the retry limit are the stored ones; ``residency_orgs``
    is counted on every call (``organizations.count_residency_orgs``, every
    org status), never cached.
    """
    llm = stored.llm
    return PlatformSettingsResponse(
        llm=SettingsLLM(
            provider=llm.provider,
            anthropic_model=llm.anthropic_model or "",
            openai_model=llm.openai_model or "",
            infomaniak_model=llm.infomaniak_model or "",
            infomaniak_available_models=await _get_infomaniak_available_models(llm.provider),
            vllm_model=llm.vllm_model or "",
            vllm_available_models=await _get_vllm_available_models(),
            max_input_tokens=llm.max_input_tokens,
            image_input=llm.image_input,
            max_retries=llm.max_retries,
            residency_orgs=await organizations.count_residency_orgs(pool),
            # Presence flags only — credential values never leave the server.
            anthropic_key_configured=bool(os.environ.get("ANTHROPIC_API_KEY")),
            openai_key_configured=bool(os.environ.get("OPENAI_API_KEY")),
            infomaniak_token_configured=bool(os.environ.get("INFOMANIAK_API_TOKEN")),
        ),
        limits=stored.limits,
        files=stored.files,
        retention=stored.retention,
        security=stored.security,
    )


async def _close_llm_client(client: LLMClient) -> None:
    """Close an LLM client best-effort: a failure is logged by class name and never raised."""
    try:
        await client.close()
    except Exception as exc:
        logger.warning("Failed to close an LLM client (%s).", type(exc).__name__)


async def get_my_settings(principal: _PrincipalDep) -> UserSettingsResponse:
    """Handle GET /api/me/settings — the caller's own theme and notifications.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        UserSettingsResponse: the stored values, or the defaults without a row.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/me/settings/get", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    return await scoped_settings.get_user_settings(get_pool(), actor=principal)


async def patch_my_settings(
    principal: _PrincipalDep, body: UserSettingsPatch
) -> UserSettingsResponse:
    """Handle PATCH /api/me/settings — change the caller's own theme and/or notifications.

    Args:
        principal: The logged-in principal (401 without a session).
        body: Validated UserSettingsPatch (422 without echo otherwise).

    Returns:
        UserSettingsResponse: the stored values after the change.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/me/settings/patch", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    return await scoped_settings.update_user_settings(get_pool(), actor=principal, patch=body)


async def reset_my_settings(principal: _PrincipalDep) -> UserSettingsResponse:
    """Handle POST /api/me/settings/reset — revert the caller's own settings (GH-35).

    Only the caller's theme and notifications: never the account (names,
    languages), the connected accounts or the org and platform settings.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        UserSettingsResponse: the defaults.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ACCOUNT_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/me/settings/reset", _user_caller(principal))
    _require_capability(principal, Capability.ACCOUNT_MANAGE)

    from admino.database import get_pool

    return await scoped_settings.reset_user_settings(get_pool(), actor=principal)


# The 400 of an org trash retention outside the platform's bounds (GH-169).
# Fixed text: never the refused value or the bounds.
_ORG_TRASH_BOUNDS_BODY: Final = {
    "detail": "The trash retention must be within the platform's bounds.",
    "reason": "trash_retention_bounds",
}


async def get_org_settings(principal: _PrincipalDep) -> OrgSettingsResponse:
    """Handle GET /api/org/settings — the settings of the Org Admin's own org.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        OrgSettingsResponse: the profile, instructions, session policy,
        effective trash retention with the platform's bounds and tool
        services (column defaults without an org_settings row), plus the
        read-only data residency and plan.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_SETTINGS_MANAGE`` and
            ``Capability.ORG_INSTRUCTIONS_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/org/settings/get", _user_caller(principal))
    _require_capability(principal, Capability.ORG_SETTINGS_MANAGE)
    # The response carries the org instructions, so their capability is
    # required too (defense in depth; the service checks both again).
    _require_capability(principal, Capability.ORG_INSTRUCTIONS_MANAGE)

    from admino.database import get_pool

    return await scoped_settings.get_org_settings(get_pool(), actor=principal)


async def patch_org_settings(
    request: Request, principal: _PrincipalDep, body: OrgSettingsPatch
) -> OrgSettingsResponse | JSONResponse:
    """Handle PATCH /api/org/settings — change the settings of the Org Admin's own org.

    Each changed section (profile, instructions, security, retention, tools)
    is one ``org.settings_change`` audit event in the same transaction (an
    audit failure is a 500 with nothing written). A changed session policy
    re-times the org's open sessions in that transaction. The org's next chat
    run loads the new tool switches with its tool policy (GH-161).

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        body: Validated OrgSettingsPatch (422 without echo otherwise).

    Returns:
        OrgSettingsResponse: the org's settings after the change, or a 400
        ``{"detail", "reason": "trash_retention_bounds"}`` with nothing
        written when a changed trash retention is outside the platform's
        bounds.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_SETTINGS_MANAGE`` and
            ``Capability.ORG_INSTRUCTIONS_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/org/settings/patch", _user_caller(principal))
    _require_capability(principal, Capability.ORG_SETTINGS_MANAGE)
    # Every response carries the instructions: see get_org_settings.
    _require_capability(principal, Capability.ORG_INSTRUCTIONS_MANAGE)

    from admino.database import get_pool

    try:
        return await scoped_settings.update_org_settings(
            get_pool(),
            actor=principal,
            patch=body,
            ip=request.client.host if request.client is not None else None,
        )
    except scoped_settings.InvalidOrgSettingsError:
        return JSONResponse(status_code=400, content=_ORG_TRASH_BOUNDS_BODY)


async def get_platform_settings(principal: _PrincipalDep) -> PlatformSettingsResponse:
    """Handle GET /api/platform/settings — the platform defaults (Super Admin).

    Reads the platform row as stored, which also refreshes the settings cache.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        PlatformSettingsResponse: the stored LLM (with the probed model lists,
        key presence flags, the model capabilities, the retry limit and the
        current number of residency orgs), limits, files, retention and
        security.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.PLATFORM_DEFAULTS_MANAGE`` (both before any database
            work or provider probe).
    """
    _check_rate_limit("/api/platform/settings/get", _user_caller(principal))
    _require_capability(principal, Capability.PLATFORM_DEFAULTS_MANAGE)

    from admino.database import get_pool

    pool = get_pool()
    stored = await scoped_settings.load_platform_settings(pool)
    return await _platform_settings_response(pool, stored)


# The 400 of a patch whose merged trash retention minimum exceeds the maximum.
_TRASH_ORDER_REFUSED: Final = "The trash retention minimum can't exceed the maximum."
# The 409 of a switch to a non-Swiss LLM provider without the right residency-org
# count (GH-242). Fixed text: never a provider, model or org value.
_RESIDENCY_CONFIRMATION_DETAIL: Final = (
    "The selected provider isn't Swiss-hosted. Confirm the number of organizations "
    "with data residency to switch."
)


def _residency_confirmation_needed(
    body: PlatformSettingsPatch, stored: scoped_settings.StoredPlatformLLM
) -> bool:
    """Whether the patch switches the LLM to a provider outside Switzerland (GH-242).

    True when the patch's ``llm.provider`` is given, is not in
    ``llm_policy.SWISS_PROVIDERS`` and differs from the stored provider. Any
    other patch needs no confirmation and ignores a given count.
    """
    target = None if body.llm is None else body.llm.provider
    return not (target is None or target in llm_policy.SWISS_PROVIDERS or target == stored.provider)


def _residency_confirmation_refusal(residency_orgs: int) -> JSONResponse:
    """The 409 of an unconfirmed switch to a non-Swiss LLM provider (GH-242).

    The body is ``{"detail", "reason": "residency_confirmation",
    "residency_orgs": <current count>}``: fixed text and a count only.
    """
    return JSONResponse(
        status_code=409,
        content={
            "detail": _RESIDENCY_CONFIRMATION_DETAIL,
            "reason": "residency_confirmation",
            "residency_orgs": residency_orgs,
        },
    )


def _new_platform_llm_client(
    config: AppConfig, stored: scoped_settings.StoredPlatformLLM, patch: SettingsPatchLLM
) -> LLMClient | None:
    """Validate a platform LLM patch and build the client it needs, before anything is written.

    The given fields are merged over the stored LLM and validated as an
    ``LLMConfig`` (the config's other llm fields kept; the retry limit is no
    ``LLMConfig`` field and stays out of the merge). A provider change always
    needs a new client; so does a model change of the vllm or infomaniak
    provider when it is the active one. A capability or retry-limit change
    alone never does.

    Returns:
        The new client, or None when the running one stays.

    Raises:
        HTTPException: 400 when the merged LLM config is invalid or its client
            can't be built.
    """
    from admino.config import LLMConfig
    from admino.llm import create_llm_client

    current = stored.model_dump(exclude={"max_retries"})
    merged = {**current, **patch.model_dump(exclude_none=True, exclude={"max_retries"})}
    try:
        new_llm_config = LLMConfig.model_validate({**config.llm.model_dump(mode="json"), **merged})
    except ValidationError as exc:
        safe_errors = [
            {"loc": [str(loc) for loc in err["loc"]], "msg": err["msg"], "type": err["type"]}
            for err in exc.errors(include_input=False)
        ]
        raise HTTPException(status_code=400, detail=safe_errors) from None

    provider = new_llm_config.provider
    model_field = f"{provider}_model"
    reinit = provider != current["provider"] or (
        provider in ("vllm", "infomaniak") and merged[model_field] != current[model_field]
    )
    if not reinit:
        return None
    try:
        return create_llm_client(new_llm_config)
    except (ValueError, ImportError) as exc:
        logger.error("Failed to create LLM client: %s", type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Failed to create LLM client for the selected provider",
        ) from None


async def patch_platform_settings(
    request: Request, principal: _PrincipalDep, body: PlatformSettingsPatch
) -> PlatformSettingsResponse | JSONResponse:
    """Handle PATCH /api/platform/settings — change the platform defaults (Super Admin).

    Any of the five sections (llm, limits, files, retention, security). When
    ``llm`` is given, the stored LLM is read from the row (which refreshes the
    settings cache). A switch to a non-Swiss provider (not infomaniak or
    vllm) needs ``confirm_residency_orgs`` equal to the current number of
    residency orgs (GH-242): otherwise the answer is a 409 with nothing built,
    written or audited. The write counts again under its row lock; a count
    that changed in between is the same 409 (the new client closed, nothing
    written). Then the llm fields are merged over the stored LLM and
    validated as an ``LLMConfig`` (the config's other llm fields kept); a
    provider change, or a model change of the active vllm/infomaniak provider,
    builds the new client BEFORE anything is written (a no-op, or a change of
    the model capabilities or the retry limit alone, never does). The changes,
    the re-timed Super Admin sessions and the ``platform.settings_change``
    audit events share one transaction
    (``scoped_settings.update_platform_settings``). Only then is the new
    client swapped in and the old one closed (best-effort); if nothing was
    written, a newly built client is closed and the running one kept. The
    stored limits and retry limit apply to the next chat request (no
    restart).

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        body: Validated PlatformSettingsPatch (422 without echo otherwise).

    Returns:
        PlatformSettingsResponse: the platform settings after the change, or
        the 409 ``{"detail", "reason": "residency_confirmation",
        "residency_orgs"}`` of an unconfirmed switch to a non-Swiss provider.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.PLATFORM_DEFAULTS_MANAGE`` (both before any database
            work), 400 when the merged LLM config is invalid or its client
            can't be built, or when the merged trash retention minimum exceeds
            the maximum (nothing written either way).
    """
    global _config
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    _check_rate_limit("/api/platform/settings/patch", _user_caller(principal))
    _require_capability(principal, Capability.PLATFORM_DEFAULTS_MANAGE)

    from admino.database import get_pool

    pool = get_pool()
    new_client: LLMClient | None = None
    # The residency-org count the Super Admin confirmed for a non-Swiss switch;
    # the write counts again under its row lock (a change in between is a 409).
    confirmed_residency_orgs: int | None = None
    if body.llm is not None:
        stored_llm = (await scoped_settings.load_platform_settings(pool)).llm
        if _residency_confirmation_needed(body, stored_llm):
            residency_orgs = await organizations.count_residency_orgs(pool)
            if body.confirm_residency_orgs != residency_orgs:
                return _residency_confirmation_refusal(residency_orgs)
            confirmed_residency_orgs = residency_orgs
        new_client = _new_platform_llm_client(_config, stored_llm, body.llm)

    try:
        stored = await scoped_settings.update_platform_settings(
            pool,
            actor=principal,
            patch=body,
            ip=request.client.host if request.client is not None else None,
            expected_residency_orgs=confirmed_residency_orgs,
        )
    except Exception as exc:
        # Nothing was written: the running client stays, the new one is retired.
        if new_client is not None:
            await _close_llm_client(new_client)
        if isinstance(exc, scoped_settings.ResidencyConfirmationError):
            return _residency_confirmation_refusal(exc.residency_orgs)
        if isinstance(exc, scoped_settings.InvalidPlatformSettingsError):
            raise HTTPException(status_code=400, detail=_TRASH_ORDER_REFUSED) from None
        raise

    # The live config follows the stored row, so diagnostics and the
    # provider-gated probes (vLLM models, reachability) report the provider
    # that now processes messages, not the one the process started with.
    _config = scoped_settings.apply_platform_settings(_config, stored)
    if new_client is not None:
        # Single worker: the event loop serialises requests, so the swap is atomic.
        # The retired client is closed so its connection pool isn't leaked.
        old_client = _agent._llm
        _agent._llm = new_client
        await _close_llm_client(old_client)
        logger.info("LLM client re-initialised after a platform LLM change.")
    return await _platform_settings_response(pool, stored)


# ---------------------------------------------------------------------------
# Tool permission route handlers (GH-161): /api/org/permissions,
# /api/org/critical-permissions, /api/permissions/summary
# ---------------------------------------------------------------------------

_UNKNOWN_PERMISSION_DETAIL: Final = "Unknown tool action."
_HARDCODED_DENIAL_DETAIL: Final = (
    "This tool/action pair is a hardcoded denial and cannot be changed."
)
_NOT_PROMOTABLE_DETAIL: Final = "Not a promotable permission"
_NO_PENDING_PROMOTION_DETAIL: Final = "No pending promotion for this permission"
_REAUTH_REQUIRED_DETAIL: Final = "Password re-authentication is required."
_REAUTH_FAILED_DETAIL: Final = "Re-authentication failed."


async def _resolve_due_promotions(pool: asyncpg.Pool, principal: Principal) -> None:
    """Complete the principal's org's due promotions and tell that org's chats.

    ``org_permissions.resolve_due_promotions`` stores each pair whose cooldown
    has passed as 'confirm'. Then ONE ``user``-role notice naming the pairs is
    stored in every chat of the org that isn't in the trash (all its members'
    chats, GH-176 ``chats.append_org_notice``), and in no other org's chat, so
    the LLM doesn't refuse based on earlier denials in the conversation.

    GH-66: the notice MUST NOT be ``system``-role: the agent drops every
    ``system`` message in caller-supplied history (prompt-injection defence,
    GH-140). It is phrased as a neutral, factual notice, not a directive: it
    occupies the human turn slot, so it must not read as a standing
    instruction to act.

    Args:
        pool: The database pool.
        principal: A member of the org (the caller).
    """
    tenant = TenantContext.from_principal(principal)
    completed = await org_permissions.resolve_due_promotions(pool, tenant)
    if not completed:
        return
    names = ", ".join(f"{tool}.{action}" for tool, action in completed)
    await chats.append_org_notice(
        pool,
        tenant,
        f"PERMISSION UPDATE: The following actions are now available with user "
        f"confirmation: {names}. Earlier denials for these actions no longer apply.",
    )


def _require_promotable(tool: str, action: str) -> None:
    """Raise 404 unless (tool, action) is a promotable (tier-2) denial."""
    if (tool, action) not in PROMOTABLE_DENIALS:
        raise HTTPException(status_code=404, detail=_NOT_PROMOTABLE_DETAIL)


async def get_org_permission_matrix(principal: _PrincipalDep) -> PermissionsResponse:
    """Handle GET /api/org/permissions — the Org Admin's own org's permission matrix.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        PermissionsResponse: the org's stored rows, sorted by (tool, action).

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/org/permissions/get", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_MANAGE)

    from admino.database import get_pool

    return await org_permissions.get_org_permissions(get_pool(), actor=principal)


async def patch_org_permission_matrix(
    request: Request, principal: _PrincipalDep, body: PermissionPatch
) -> PermissionsResponse:
    """Handle PATCH /api/org/permissions — change one permission of the Org Admin's org.

    A real change is an ``org.permission_change`` audit event in the same
    transaction (an audit failure is a 500 with nothing written). The org's
    next chat run loads the new matrix.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        body: Validated PermissionPatch (422 without echo otherwise).

    Returns:
        PermissionsResponse: the org's full matrix after the change.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_MANAGE`` (both before any database
            work); 400 for an unknown pair or a hardcoded denial (nothing read
            or written).
    """
    _check_rate_limit("/api/org/permissions/patch", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_MANAGE)

    from admino.database import get_pool

    try:
        return await org_permissions.update_org_permission(
            get_pool(),
            actor=principal,
            patch=body,
            ip=request.client.host if request.client is not None else None,
        )
    except org_permissions.UnknownPermissionError:
        raise HTTPException(status_code=400, detail=_UNKNOWN_PERMISSION_DETAIL) from None
    except org_permissions.HardcodedDenialError:
        raise HTTPException(status_code=400, detail=_HARDCODED_DENIAL_DETAIL) from None


async def get_org_critical_permissions(principal: _PrincipalDep) -> CriticalPermissionsResponse:
    """Handle GET /api/org/critical-permissions — the org's four promotable permissions.

    The org's due promotions are completed first.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        CriticalPermissionsResponse: each pair's state and pending time.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_MANAGE`` (both before any database work).
    """
    _check_rate_limit("/api/org/critical-permissions/get", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_MANAGE)

    from admino.database import get_pool

    pool = get_pool()
    await _resolve_due_promotions(pool, principal)
    return await org_permissions.critical_permissions(pool, actor=principal)


async def patch_org_critical_permission(
    request: Request,
    principal: _PrincipalDep,
    tool: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
    action: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
    body: CriticalPermissionPromote | None = None,
) -> CriticalPermissionState:
    """Handle PATCH /api/org/critical-permissions/{tool}/{action} — demote or promote.

    After the org's due promotions are completed: a promoted pair (stored
    'confirm') is demoted at once, with no password (a body is ignored);
    otherwise the body's password re-authenticates the Org Admin and starts
    the pair's 5-minute promotion cooldown. Both are audited.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        tool: The tool name (identifier pattern; 422 otherwise).
        action: The action name (identifier pattern; 422 otherwise).
        body: The Org Admin's password; needed to promote (422 without echo
            when malformed).

    Returns:
        CriticalPermissionState: 'deny' after a demotion or with the pending
        time of a promotion; 'confirm' if it was already promoted.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_MANAGE`` (both before any database
            work); 404 for a pair that isn't promotable (no re-auth); 400 for
            a promotion without a password; 403 when the re-authentication
            fails (nothing pending or recorded).
    """
    _check_rate_limit("/api/org/critical-permissions/promote", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_MANAGE)
    _require_promotable(tool, action)

    from admino.database import get_pool

    pool = get_pool()
    ip = request.client.host if request.client is not None else None
    await _resolve_due_promotions(pool, principal)
    try:
        # A demotion checks the stored state under its row lock, so a
        # concurrent change can't slip between the check and the write.
        return await org_permissions.demote(pool, actor=principal, tool=tool, action=action, ip=ip)
    except org_permissions.NotPromotedError:
        pass  # Not promoted: this is a promotion request.
    if body is None:
        raise HTTPException(status_code=400, detail=_REAUTH_REQUIRED_DETAIL)
    try:
        return await org_permissions.request_promotion(
            pool,
            actor=principal,
            tool=tool,
            action=action,
            password=body.password.get_secret_value(),
            ip=ip,
        )
    except org_permissions.ReauthFailedError:
        raise HTTPException(status_code=403, detail=_REAUTH_FAILED_DETAIL) from None


async def cancel_org_critical_permission_pending(
    request: Request,
    principal: _PrincipalDep,
    tool: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
    action: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
) -> CriticalPermissionState:
    """Handle DELETE /api/org/critical-permissions/{tool}/{action}/pending — cancel it.

    After the org's due promotions are completed (a completed one can't be
    cancelled any more), the org's pending promotion of the pair is dropped
    and ``org.permission_promote_cancel`` is recorded.

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        tool: The tool name (identifier pattern; 422 otherwise).
        action: The action name (identifier pattern; 422 otherwise).

    Returns:
        CriticalPermissionState: 'deny', no pending time.

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_MANAGE`` (both before any database
            work); 404 for a pair that isn't promotable, or without a pending
            promotion in the org.
    """
    _check_rate_limit("/api/org/critical-permissions/cancel", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_MANAGE)
    _require_promotable(tool, action)

    from admino.database import get_pool

    pool = get_pool()
    await _resolve_due_promotions(pool, principal)
    try:
        return await org_permissions.cancel_promotion(
            pool,
            actor=principal,
            tool=tool,
            action=action,
            ip=request.client.host if request.client is not None else None,
        )
    except org_permissions.NoPendingPromotionError:
        raise HTTPException(status_code=404, detail=_NO_PENDING_PROMOTION_DETAIL) from None


async def get_permissions_summary(principal: _PrincipalDep) -> PermissionsSummaryResponse:
    """Handle GET /api/permissions/summary — the caller's org's effective permissions.

    Read-only, for every member role. The org's due promotions are completed
    first.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        PermissionsSummaryResponse: each stored (tool, action) of the org with
        its effective state ("disabled" for a switched-off service).

    Raises:
        HTTPException: 429 when rate-limited, 403 without
            ``Capability.ORG_PERMISSIONS_VIEW`` (every member role has it, so
            only the Super Admin is refused; both before any database work).
    """
    _check_rate_limit("/api/permissions/summary/get", _user_caller(principal))
    _require_capability(principal, Capability.ORG_PERMISSIONS_VIEW)

    from admino.database import get_pool

    pool = get_pool()
    await _resolve_due_promotions(pool, principal)
    return await org_permissions.permissions_summary(pool, actor=principal)


# ---------------------------------------------------------------------------
# OAuth route handlers
# ---------------------------------------------------------------------------


def _reap_oauth_states(user_id: UUID) -> None:
    """Drop the expired pending states and the given user's earlier one.

    Removes every entry older than ``_OAUTH_STATE_TTL_S`` seconds and every
    entry of ``user_id`` (their earlier authorization is dead anyway: the new
    one overwrites its binding cookie). Another user's fresh entry is never
    removed, so one user, or org, can't break another's connect flow. This is
    a synchronous function (no ``await``) to ensure atomicity within the
    single-threaded asyncio event loop.
    """
    now = time.time()
    stale = [
        s
        for s, entry in _oauth_pending_states.items()
        if now - entry.created_at > _OAUTH_STATE_TTL_S or entry.user_id == user_id
    ]
    for s in stale:
        del _oauth_pending_states[s]


def _build_oauth_redirect_uri() -> str:
    """Build the OAuth callback redirect URI.

    Reads ``OAUTH_REDIRECT_URI`` from the environment if set (preferred —
    must match the URI registered in the OAuth provider's console). Falls
    back to constructing from server config (host + port).

    Returns:
        The fully-qualified callback URL string.

    Security notes:
        The redirect URI is deterministic from config/env — never derived
        from untrusted request headers (Host, X-Forwarded-*).
    """
    env_uri = os.environ.get("OAUTH_REDIRECT_URI")
    if env_uri:
        return env_uri
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    host = "localhost" if _config.server.host == "0.0.0.0" else _config.server.host  # noqa: S104
    return f"http://{host}:{_config.server.port}/api/oauth/callback"


def _oauth_cookie_secure() -> bool:
    """Whether the OAuth binding cookie is Secure: ``server.cookie_secure`` (on without config)."""
    return _config.server.cookie_secure if _config is not None else True


def _oauth_redirect(location: str) -> RedirectResponse:
    """A callback redirect (307) that also deletes the binding cookie (same Path)."""
    response = RedirectResponse(url=location, status_code=307)
    response.delete_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        path=_OAUTH_CALLBACK_PATH,
        secure=_oauth_cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    return response


def _oauth_error(reason: str) -> RedirectResponse:
    """The callback's error redirect: ``/tools?oauth=error&reason=<reason>``."""
    return _oauth_redirect(f"/tools?oauth=error&reason={reason}")


async def _oauth_authorize(
    session: sessions.AuthenticatedSession, response: Response, provider: OAuthProvider
) -> OAuthAuthorizeResponse:
    """Build the provider's consent URL and bind its state to the caller's session.

    Order: the per-user bucket, ``oauth.connect`` (403 ``Forbidden`` for a
    Viewer or a Super Admin), the org's data residency (403
    ``OAUTH_RESIDENCY_DETAIL``), the consent URL; only then the pending state
    and the binding cookie, so a refused request stores and sets nothing.

    Args:
        session: The caller's resolved session (its id is bound to the state).
        response: The response the binding cookie is set on.
        provider: ``"google"`` or ``"microsoft"``.

    Returns:
        OAuthAuthorizeResponse with the consent URL.

    Raises:
        HTTPException: 429 when rate-limited, 403 without ``oauth.connect`` or
            under residency, 500 if the provider's OAuth env vars are missing.
    """
    principal = session.principal
    _check_rate_limit(f"/api/oauth/{provider}/authorize", _user_caller(principal))
    _require_capability(principal, Capability.OAUTH_CONNECT)

    from admino.database import get_pool

    if await scoped_settings.org_residency(get_pool(), TenantContext.from_principal(principal)):
        raise HTTPException(status_code=403, detail=OAUTH_RESIDENCY_DETAIL)

    _reap_oauth_states(principal.user_id)
    redirect_uri = _build_oauth_redirect_uri()
    build_consent_url = (
        build_google_consent_url if provider == "google" else build_microsoft_consent_url
    )
    try:
        url, state = build_consent_url(redirect_uri)
    except OAuthError:
        logger.error(
            "Failed to build %s consent URL — check OAuth env vars.", provider.capitalize()
        )
        raise HTTPException(status_code=500, detail="OAuth configuration error.")  # noqa: B904

    _oauth_pending_states[state] = OAuthPendingState(
        time.time(), provider, redirect_uri, principal.user_id, session.session_id
    )
    response.set_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        value=state,
        max_age=_OAUTH_STATE_TTL_S,
        path=_OAUTH_CALLBACK_PATH,
        secure=_oauth_cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    logger.info("%s OAuth authorize URL generated.", provider.capitalize())
    return OAuthAuthorizeResponse(url=url)


async def oauth_google_authorize(
    session: _SessionDep, response: Response
) -> OAuthAuthorizeResponse:
    """Handle GET /api/oauth/google/authorize — start connecting the caller's Google account.

    See ``_oauth_authorize`` (``oauth.connect``, residency, the session-bound
    state and the binding cookie).

    Args:
        session: The caller's resolved session (401 without one).
        response: The response the binding cookie is set on.

    Returns:
        OAuthAuthorizeResponse with the consent URL.
    """
    return await _oauth_authorize(session, response, "google")


async def oauth_microsoft_authorize(
    session: _SessionDep, response: Response
) -> OAuthAuthorizeResponse:
    """Handle GET /api/oauth/microsoft/authorize — start connecting the caller's Microsoft account.

    See ``_oauth_authorize`` (``oauth.connect``, residency, the session-bound
    state and the binding cookie).

    Args:
        session: The caller's resolved session (401 without one).
        response: The response the binding cookie is set on.

    Returns:
        OAuthAuthorizeResponse with the consent URL.
    """
    return await _oauth_authorize(session, response, "microsoft")


async def oauth_callback(
    request: Request,
    code: str | None = Query(default=None, max_length=2048, pattern=r"^[A-Za-z0-9/_.\-+=!*~,]+$"),
    state: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$"),
    error: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_]+$"),
) -> RedirectResponse:
    """Handle the OAuth callback redirect for Google and Microsoft.

    No session required: this endpoint is the provider's cross-site redirect
    (a SameSite=Strict session cookie isn't sent on it). The state, its
    binding cookie and the initiating session protect it instead (GH-162).
    Rate-limited per client IP. Checks, in order:

    1. a known ``state`` (else ``invalid_state``); its pending entry is popped
       at once, so every state is one-shot;
    2. the ``admino_oauth_state`` cookie equals the state (constant-time),
       and the entry is at most ``_OAUTH_STATE_TTL_S`` old (else
       ``invalid_state``);
    3. the provider's ``error`` (``denied``), a ``code`` (``missing_code``);
    4. the initiating session still resolves, for the initiating user (else
       ``invalid_state``); that user still has ``oauth.connect``
       (``forbidden``); their org has no data residency (``residency``);
    5. the code exchange, encryption and ``save_token`` for the initiating
       user (``exchange_failed`` on any OAuthError); then that user's cached
       access token is invalidated.

    Every outcome is a 307 to ``/tools?oauth=success`` or
    ``/tools?oauth=error&reason=<reason>`` that deletes the binding cookie.

    Args:
        request: The incoming request (its client IP keys the rate limit, its
            cookies carry the binding cookie).
        code: Authorization code from the provider (present on success).
        state: CSRF state token (must match a pending state).
        error: Error string from the provider (present on user denial).

    Returns:
        RedirectResponse to the tools page with oauth status query params.

    Security notes:
        - Nothing is stored on any error; the session, role and residency
          checks run before any token-endpoint call.
        - The token is stored for the initiating user only, whatever session
          cookie the callback request carries.
        - Tokens are Fernet-encrypted before being written to the database.
        - Never logs credentials, tokens, codes, state values or emails.
    """
    _check_rate_limit("/api/oauth/callback", f"ip:{_client_ip(request)}")

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    # Validate the CSRF state first (RFC 6749 §10.12), before inspecting any
    # other parameter, the provider's error included. Pop it: one-shot.
    entry = _oauth_pending_states.pop(state, None) if state else None
    if state is None or entry is None:
        logger.warning("OAuth callback received invalid or missing state.")
        return _oauth_error("invalid_state")

    provider = entry.provider
    label = provider.capitalize()
    cookie = request.cookies.get(OAUTH_STATE_COOKIE_NAME)
    if cookie is None or not secrets.compare_digest(cookie.encode(), state.encode()):
        logger.warning("%s OAuth callback without a matching state cookie.", label)
        return _oauth_error("invalid_state")
    if time.time() - entry.created_at > _OAUTH_STATE_TTL_S:
        logger.warning("%s OAuth callback received expired state token.", label)
        return _oauth_error("invalid_state")

    # Provider denied consent.
    if error:
        logger.info("%s OAuth callback received denial from user.", label)
        return _oauth_error("denied")

    # Missing authorization code.
    if not code:
        logger.warning("%s OAuth callback missing authorization code.", label)
        return _oauth_error("missing_code")

    from admino.database import get_pool

    pool = get_pool()
    session = await sessions.resolve_session_by_id(pool, entry.session_id)
    if session is None or session.principal.user_id != entry.user_id:
        logger.warning("%s OAuth callback: the initiating session has ended.", label)
        return _oauth_error("invalid_state")
    principal = session.principal
    if not can(principal, Capability.OAUTH_CONNECT):
        logger.warning("%s OAuth callback: the initiating user can't connect accounts.", label)
        return _oauth_error("forbidden")
    tenant = TenantContext.from_principal(principal)
    if await scoped_settings.org_residency(pool, tenant):
        logger.info("%s OAuth callback refused: data residency is on.", label)
        return _oauth_error("residency")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
        ) as client:
            if provider == "google":
                access_token, refresh_token, scopes = await exchange_google_code(
                    code, entry.redirect_uri, client
                )
                # Best-effort: fetch user email for display purposes.
                email = await get_google_user_email(access_token, client)
            else:
                access_token, refresh_token, scopes = await exchange_microsoft_code(
                    code, entry.redirect_uri, client
                )
                email = None

            # Access token is only needed for the best-effort email lookup
            # above; it is never persisted. Drop it before encrypting the
            # refresh token to minimise in-memory exposure of plaintext tokens.
            del access_token

            # Encrypt and persist the refresh token, then clear plaintext
            # from the local scope to minimise in-memory exposure.
            encrypted = encrypt_refresh_token(refresh_token)
            del refresh_token
            now_utc = datetime.now(UTC)
            token = OAuthToken(
                provider=provider,
                scopes=scopes,
                encrypted_refresh_token=encrypted,
                email=email,
                created_at=now_utc,
                last_refreshed_at=now_utc,
            )
            await save_token(pool, tenant, token)
    except OAuthError:
        logger.error("%s OAuth token exchange or storage failed.", label)
        return _oauth_error("exchange_failed")

    # A reconnect must never serve the previous account's cached access token.
    await access_tokens.invalidate(entry.user_id, provider)

    if email:
        logger.info("%s OAuth connected successfully for user.", label)
    else:
        logger.info("%s OAuth connected successfully (email not retrieved).", label)

    return _oauth_redirect("/tools?oauth=success")


async def _oauth_status(principal: Principal, provider: OAuthProvider) -> OAuthConnectionStatus:
    """The caller's own connection to ``provider``, the org's services and residency.

    Args:
        principal: The logged-in principal.
        provider: ``"google"`` or ``"microsoft"``.

    Returns:
        OAuthConnectionStatus: ``connected``/``healthy`` of the caller's own
        row (never another user's), the org's ``data_residency``, and the
        provider's services with the org's stored switches.

    Raises:
        HTTPException: 429 when rate-limited, 403 without ``oauth.connect``
            (both before any database work).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit(f"/api/oauth/{provider}/status", _user_caller(principal))
    _require_capability(principal, Capability.OAUTH_CONNECT)

    from admino.database import get_pool

    pool = get_pool()
    tenant = TenantContext.from_principal(principal)
    connected, healthy = await get_connection_status(pool, tenant, provider)
    switches = await scoped_settings.org_tools_enabled(pool, tenant)
    return OAuthConnectionStatus(
        connected=connected,
        healthy=healthy,
        data_residency=await scoped_settings.org_residency(pool, tenant),
        services=[
            OAuthServiceStatus(tool=tool, enabled=switches[tool])
            for tool in PROVIDER_TOOLS[provider]
        ],
    )


async def oauth_google_status(principal: _PrincipalDep) -> OAuthConnectionStatus:
    """Handle GET /api/oauth/google/status — the caller's own Google connection.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        OAuthConnectionStatus (see ``_oauth_status``); never token contents.
    """
    return await _oauth_status(principal, "google")


async def oauth_microsoft_status(principal: _PrincipalDep) -> OAuthConnectionStatus:
    """Handle GET /api/oauth/microsoft/status — the caller's own Microsoft connection.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        OAuthConnectionStatus (see ``_oauth_status``); never token contents.
    """
    return await _oauth_status(principal, "microsoft")


async def _oauth_disconnect(principal: Principal, provider: OAuthProvider) -> dict[str, str]:
    """Revoke and delete the caller's own connection to ``provider``.

    Allowed while the org's data residency is on (the user may remove a kept
    connection). The caller's cached access token is invalidated afterwards.

    Args:
        principal: The logged-in principal.
        provider: ``"google"`` or ``"microsoft"``.

    Returns:
        ``{"status": "disconnected"}``.

    Raises:
        HTTPException: 429 when rate-limited, 403 without ``oauth.connect``
            (both before any database work), 404 when the caller has no
            connection, 500 if the deletion fails.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit(f"/api/oauth/{provider}/disconnect", _user_caller(principal))
    _require_capability(principal, Capability.OAUTH_CONNECT)

    from admino.database import get_pool

    label = provider.capitalize()
    tenant = TenantContext.from_principal(principal)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        ) as client:
            deleted = await revoke_and_delete_token(get_pool(), tenant, provider, client)
    except OAuthError:
        logger.error("Failed to disconnect %s account.", label)
        raise HTTPException(status_code=500, detail="Failed to disconnect.")  # noqa: B904

    if not deleted:
        raise HTTPException(status_code=404, detail=f"{label} account is not connected.")

    # The tools must stop reusing the caller's cached access token now that
    # the refresh token row is gone.
    await access_tokens.invalidate(principal.user_id, provider)

    logger.info("%s OAuth account disconnected.", label)
    return {"status": "disconnected"}


async def oauth_google_disconnect(principal: _PrincipalDep) -> dict[str, str]:
    """Handle DELETE /api/oauth/google — disconnect the caller's own Google account.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        ``{"status": "disconnected"}`` (see ``_oauth_disconnect``).
    """
    return await _oauth_disconnect(principal, "google")


async def oauth_microsoft_disconnect(principal: _PrincipalDep) -> dict[str, str]:
    """Handle DELETE /api/oauth/microsoft — disconnect the caller's own Microsoft account.

    Args:
        principal: The logged-in principal (401 without a session).

    Returns:
        ``{"status": "disconnected"}`` (see ``_oauth_disconnect``).
    """
    return await _oauth_disconnect(principal, "microsoft")


# ---------------------------------------------------------------------------
# Validation error handler
# ---------------------------------------------------------------------------


async def _validation_error_handler(
    request: Request,
    exc: ValidationError,
) -> JSONResponse:
    """Handle Pydantic validation errors without leaking input values.

    Returns a generic 422 response. Raw input values are never included
    in the response body.

    Args:
        request: The incoming request (unused but required by FastAPI).
        exc: The Pydantic ValidationError.

    Returns:
        JSONResponse with safe error details.
    """
    safe_errors = []
    for err in exc.errors(include_input=False):
        safe_errors.append(
            {
                "loc": [str(loc) for loc in err["loc"]],
                "msg": err["msg"],
                "type": err["type"],
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


async def _request_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle FastAPI request validation errors without leaking input values.

    FastAPI raises RequestValidationError (not pydantic.ValidationError)
    for request body/query/path validation failures. We extract only the
    safe fields (loc, msg, type) and explicitly exclude 'input', 'ctx',
    and 'url' to prevent raw user values from appearing in the response.

    Args:
        request: The incoming request (unused but required by FastAPI).
        exc: The FastAPI RequestValidationError wrapping Pydantic errors.

    Returns:
        JSONResponse with safe error details (no raw input values).
    """
    safe_errors = []
    for err in exc.errors():
        safe_errors.append(
            {
                "loc": [str(loc) for loc in err.get("loc", [])],
                "msg": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


# The chat routes' documented errors (GH-176), one body each wherever they are
# raised (the repository, the chat runtime), so no route answers them otherwise.


async def _chat_not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    """``chats.ChatNotFoundError``: the 404 ``chat_not_found``.

    One body for an unknown id, another org's or another user's chat and a
    trashed one, so a 404 never tells whether a chat exists.
    """
    return JSONResponse(status_code=404, content=_CHAT_NOT_FOUND_BODY)


async def _invalid_cursor_handler(request: Request, exc: Exception) -> JSONResponse:
    """``chats.InvalidCursorError``: the 422 ``invalid_cursor`` (the cursor isn't echoed)."""
    return JSONResponse(status_code=422, content=_INVALID_CURSOR_BODY)


async def _chats_busy_handler(request: Request, exc: Exception) -> JSONResponse:
    """``ChatRuntimeFullError``: the 503 ``chats_busy`` (no runtime entry can be evicted)."""
    return JSONResponse(status_code=503, content=_CHATS_BUSY_BODY)


async def _user_chats_busy_handler(request: Request, exc: Exception) -> JSONResponse:
    """``ChatRuntimeUserLimitError``: the 429 ``rate_limit`` (GH-24).

    The caller's runtime entries are all in use or hold a pending
    confirmation; raised before any agent run, with nothing stored.
    """
    return JSONResponse(status_code=429, content=_USER_CHATS_BUSY_BODY)


async def _run_active_handler(request: Request, exc: Exception) -> JSONResponse:
    """``ChatRunActiveError``: the 409 ``run_active`` (GH-8).

    A message to a chat whose run is going; refused before any run, with
    nothing stored, streamed or not.
    """
    return JSONResponse(status_code=409, content=_RUN_ACTIVE_BODY)


async def _attachment_not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    """``attachments.AttachmentNotFoundError``: the 404 ``attachment_not_found`` (GH-187).

    One body for an unknown id, another org's or another user's attachment, a
    trashed one and one whose file is gone, so a 404 never tells whether a file
    exists.
    """
    return JSONResponse(status_code=404, content=_ATTACHMENT_NOT_FOUND_BODY)


async def _attachment_already_sent_handler(request: Request, exc: Exception) -> JSONResponse:
    """``attachments.AttachmentAlreadySentError``: the 409 ``attachment_already_sent``.

    GH-187: a message listing a file another message carried; refused before
    the run, with nothing stored.
    """
    return JSONResponse(status_code=409, content=_ATTACHMENT_ALREADY_SENT_BODY)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


async def _recover_attachments() -> None:
    """Queue again the attachments a restart left unprocessed (GH-187), once at startup.

    ``attachment_processing.recover`` with the pool, ``_processing`` and the
    attachments root, all looked up now. A failure is logged by its class name
    only (its message may name a path) and never stops the app.
    """
    from admino.database import get_pool

    try:
        await attachment_processing.recover(get_pool(), _processing, attachments.attachments_root())
    except Exception as exc:
        # Startup goes on: the files stay queued in the database for the next start.
        logger.warning("Attachment recovery failed: %s", type(exc).__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application lifespan — init DB pool, the audit retention job, the
    expired-session purge, the organization purge, the expired login-throttle
    purge, the expired-confirmation reaper, the attachment orphan GC and the
    one-shot attachment recovery and, when SMTP is configured, the email
    outbox sender on startup; on shutdown, stop the detached streamed runs and
    wait for them (at most ``_DRAIN_TIMEOUT_S``, GH-8), then stop the
    background tasks and the attachment processing pool, then close the pool.

    The pool must be created here (on uvicorn's event loop), not in main(),
    because asyncio.run() closes its event loop on return, which would
    invalidate any connections created there.

    GH-220: the pool connects as the least-privilege runtime role
    ``admino_app`` (``database_url_from_env``), never as the database owner;
    without PG_APP_PASSWORD the app refuses to start.
    """
    from admino.audit_events import run_retention_job
    from admino.database import close_pool, database_url_from_env, get_pool, init_pool
    from admino.email_outbox import run_outbox_sender
    from admino.mailer import load_smtp_config

    database_url = database_url_from_env()
    if database_url is None:
        msg = "PG_APP_PASSWORD environment variable is required but not set."
        raise RuntimeError(msg)

    await init_pool(database_url)

    # GH-146: the daily audit retention purge runs while the app is up. The
    # task stays referenced here and is cancelled before the pool closes.
    # GH-160: each run reads the stored retention.audit_months (the cached
    # platform settings), so a change applies to the next run.
    async def audit_months() -> int:
        return (await scoped_settings.current_platform_settings(get_pool())).retention.audit_months

    retention_task = asyncio.create_task(
        run_retention_job(get_pool(), retention_months=audit_months)
    )

    # GH-152: expired and idle session rows are purged hourly while the app is
    # up. Looked up at call time, like the retention job; cancelled before the
    # pool closes.
    session_purge_task = asyncio.create_task(sessions.run_session_purge_job(get_pool()))

    # GH-154: organizations whose deletion grace period is over (and #147's
    # default organization, which migration 0011 made due) are purged now and
    # then hourly while the app is up. Looked up at call time, like the session
    # purge; cancelled before the pool closes.
    org_purge_task = asyncio.create_task(organizations.run_org_purge_job(get_pool()))

    # GH-157: login_throttle rows past their expiry (ended failure windows and
    # lockouts) are purged now and then hourly while the app is up. Looked up
    # at call time, like the session purge; cancelled before the pool closes.
    throttle_purge_task = asyncio.create_task(login_throttle.run_purge_job(get_pool()))

    # GH-148: the outbox sender delivers queued transactional email while the
    # app is up. Without SMTP config (load_smtp_config logs which variables are
    # missing) nothing starts and mail stays queued. Cancelled before the pool
    # closes, like the retention task.
    smtp_config = load_smtp_config()
    sender_task = (
        asyncio.create_task(run_outbox_sender(get_pool(), smtp_config))
        if smtp_config is not None
        else None
    )

    # GH-24: expired pending confirmations are reaped every 30 seconds while the app
    # is up, even without a chat request (memory only: no query, no chat lock).
    # Looked up at call time, like the session purge; cancelled before the pool
    # closes.
    confirmation_reaper_task = asyncio.create_task(_run_confirmation_reaper())

    # GH-187: attachments never sent within 24 hours and stray files are removed now
    # and then hourly; files a restart left uploaded or processing are queued again
    # once (the startup doesn't wait for it). Looked up at call time, like the
    # session purge; cancelled before the pool closes.
    attachment_gc_task = asyncio.create_task(attachment_gc.run_gc_job(get_pool()))
    attachment_recovery_task = asyncio.create_task(_recover_attachments())

    # GH-161: no tools gate or promoted permissions are loaded into the agent:
    # every chat run loads its own org's tool policy.

    yield
    # GH-8: a detached streamed run outlives its request (uvicorn waits only for
    # those), so the shutdown asks each one to stop and waits for it (bounded)
    # before anything it needs goes: a run whose client left may be inside a tool
    # call whose tool.call audit row and turn are still to be written.
    unfinished = await event_stream.drain(_DRAIN_TIMEOUT_S)
    if unfinished:
        logger.warning("Shutdown: %d streamed chat runs still running", unfinished)
    # GH-187: no recovery, GC pass or processing job outlives the pool. The recovery
    # stops first, so it queues nothing into the closed processing pool.
    attachment_recovery_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await attachment_recovery_task
    attachment_gc_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await attachment_gc_task
    await _processing.close()
    confirmation_reaper_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await confirmation_reaper_task
    retention_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await retention_task
    session_purge_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await session_purge_task
    org_purge_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await org_purge_task
    throttle_purge_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await throttle_purge_task
    if sender_task is not None:
        sender_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sender_task
    await close_pool()


def create_app(
    *,
    agent: Agent,
    config: AppConfig,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Wires up routes, middleware, error handlers, and module-level state.
    The agent and config are injected to support testing with fakes.

    Args:
        agent: The Agent instance to handle user messages.
        config: Application configuration (server, limits, LLM, etc.).

    Returns:
        A configured FastAPI application ready to serve.
    """
    global _agent, _config, _processing
    _agent = agent
    _config = config

    # A fresh process state (a restart; test isolation): the chat runtime's
    # locks and pending confirmations start empty (a chat awaiting one then
    # shows it as expired), and so do the OAuth states.
    _chat_runtime.clear()
    _oauth_pending_states.clear()
    # Pending critical permission promotions start empty, like a restart (GH-161).
    org_permissions.clear_pending()
    # A fresh attachment processing pool (GH-187): no job of an earlier app carries over.
    _processing = attachment_processing.ProcessingPool()

    # Rate-limit buckets start empty (fresh process state, test isolation).
    _rate_buckets.clear()

    app = FastAPI(
        title="admino",
        description="Local-only, security-first personal AI agent",
        version="0.1.0",
        docs_url=None,  # Disable Swagger UI in production
        redoc_url=None,  # Disable ReDoc in production
        openapi_url=None,  # No anonymous map of the API surface
        lifespan=_lifespan,
    )

    # --- Middleware ---
    # Starlette wraps the LAST added middleware outermost. Resulting order for a
    # request: request IDs -> turn timings -> trusted proxy headers (when
    # configured) -> CORS -> security headers -> cross-origin protection ->
    # routes. Cross-origin protection (CSRF) therefore refuses a cross-origin
    # write before authentication, rate limiting and handlers run, and its 403
    # still gets the security headers.
    app.add_middleware(CrossOriginProtectionMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # --- CORS middleware ---
    # The one allowed origin is server.public_url. The PWA is served
    # same-origin, so the session cookie never needs a cross-origin
    # credentialed request: allow_credentials stays False, and Content-Type is
    # the only allowed request header (no Authorization: there is no bearer auth).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[config.server.public_url],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

    # --- Trusted proxy headers (outside CORS and every middleware above) ---
    # Added after them, so CORS, the security headers, the CSRF check, the per-IP rate
    # limits, the audit events and the handlers all see the client address and
    # scheme the trusted reverse proxy reports. Not installed without trusted
    # proxies: X-Forwarded-* headers are then ignored from every peer.
    trusted_proxies = list(config.server.trusted_proxies)
    if trusted_proxies:
        app.add_middleware(TrustedProxyHeadersMiddleware, trusted_proxies=trusted_proxies)

    # --- Turn timings (GH-244) ---
    # Right inside the request IDs: the timing line carries the request's ID, and
    # it times every other middleware too, so a turn refused before its route (the
    # CSRF 403) still logs its one line, and the 500 the request-ID middleware
    # answers for an escaping exception is recorded as one.
    app.add_middleware(request_timing.TimingMiddleware)

    # --- Request IDs (outermost, GH-158) ---
    # Added last, so every response (the CSRF 403, 404, 422, 429, static files
    # and the 500 for an unhandled exception) carries X-Request-ID, and every
    # log line of the request carries the same ID.
    app.add_middleware(RequestIdMiddleware)

    # --- Error handlers ---
    # RequestValidationError: raised by FastAPI for request body/query/path validation.
    app.add_exception_handler(RequestValidationError, _request_validation_error_handler)  # type: ignore[arg-type]
    # ValidationError: raised by Pydantic inside route handlers (e.g. response model construction).
    app.add_exception_handler(ValidationError, _validation_error_handler)  # type: ignore[arg-type]
    # GH-176: the chat routes' documented errors.
    app.add_exception_handler(chats.ChatNotFoundError, _chat_not_found_handler)
    app.add_exception_handler(chats.InvalidCursorError, _invalid_cursor_handler)
    app.add_exception_handler(ChatRuntimeFullError, _chats_busy_handler)
    # GH-24: the caller's per-user chat-runtime bound.
    app.add_exception_handler(ChatRuntimeUserLimitError, _user_chats_busy_handler)
    # GH-8: one run per chat at a time.
    app.add_exception_handler(ChatRunActiveError, _run_active_handler)
    # GH-187: the attachment reads' and a message's files' documented errors.
    app.add_exception_handler(attachments.AttachmentNotFoundError, _attachment_not_found_handler)
    app.add_exception_handler(
        attachments.AttachmentAlreadySentError, _attachment_already_sent_handler
    )

    # --- Routes ---
    # Public: health check, login, password reset, the invitation link routes
    # and the OAuth callback (plus static files). Every other route depends on
    # require_session.
    app.get("/health", response_model=None)(health_check)
    app.post("/api/auth/login", status_code=204, response_model=None)(post_login)
    app.post("/api/auth/password-reset", status_code=202, response_model=None)(post_password_reset)
    app.post("/api/auth/password-reset/confirm", status_code=204, response_model=None)(
        post_password_reset_confirm
    )
    app.get("/api/auth/invitations/{token}", response_model=InvitationDetails)(
        get_invitation_details
    )
    app.post("/api/auth/invitations/{token}/accept", status_code=204, response_model=None)(
        post_invitation_accept
    )

    # API routes — session required.
    app.post("/api/auth/logout", status_code=204, response_model=None)(post_logout)
    app.get("/api/auth/me", response_model=MeResponse)(get_me)
    app.get("/api/me/sessions", response_model=SessionListResponse)(get_my_sessions)
    app.delete("/api/me/sessions/{session_id}", status_code=204, response_model=None)(
        delete_my_session
    )
    app.get("/api/me", response_model=MyAccountResponse)(get_my_account)
    app.patch("/api/me", response_model=MyAccountResponse)(patch_my_account)
    app.post("/api/me/password", status_code=204, response_model=None)(post_my_password)
    app.post("/api/org/users/{user_id}/logout", status_code=204, response_model=None)(
        post_org_user_logout
    )
    app.get("/api/org/users", response_model=OrgUserListResponse)(get_org_users)
    app.patch("/api/org/users/{user_id}", response_model=OrgUserSummary)(patch_org_user)
    app.post("/api/org/users/{user_id}/deactivate", response_model=OrgUserSummary)(
        post_org_user_deactivate
    )
    app.post("/api/org/users/{user_id}/reactivate", response_model=OrgUserSummary)(
        post_org_user_reactivate
    )
    app.delete("/api/org/users/{user_id}", status_code=204, response_model=None)(delete_org_user)
    app.post("/api/org/users/{user_id}/password-reset", status_code=202, response_model=None)(
        post_org_user_password_reset
    )
    app.post("/api/org/invitations", status_code=201, response_model=InvitationSummary)(
        post_org_invitation
    )
    app.get("/api/org/invitations", response_model=InvitationListResponse)(get_org_invitations)
    app.delete("/api/org/invitations/{invitation_id}", status_code=204, response_model=None)(
        delete_org_invitation
    )
    app.post("/api/org/invitations/{invitation_id}/resend", response_model=InvitationSummary)(
        post_org_invitation_resend
    )
    app.get("/api/platform/orgs", response_model=OrgListResponse)(get_platform_orgs)
    app.post("/api/platform/orgs", status_code=201, response_model=OrgCreateResponse)(
        post_platform_org
    )
    app.patch("/api/platform/orgs/{org_id}/limits", response_model=OrgSummary)(
        patch_platform_org_limits
    )
    app.post("/api/platform/orgs/{org_id}/deactivate", response_model=OrgSummary)(
        post_platform_org_deactivate
    )
    app.post("/api/platform/orgs/{org_id}/reactivate", response_model=OrgSummary)(
        post_platform_org_reactivate
    )
    app.post("/api/platform/orgs/{org_id}/deletion", response_model=OrgSummary)(
        post_platform_org_deletion
    )
    app.delete("/api/platform/orgs/{org_id}/deletion", response_model=OrgSummary)(
        delete_platform_org_deletion
    )
    app.patch("/api/platform/orgs/{org_id}/residency", response_model=OrgSummary)(
        patch_platform_org_residency
    )
    app.get("/api/platform/orgs/{org_id}/users", response_model=PlatformUserListResponse)(
        get_platform_org_users
    )
    app.get("/api/platform/orgs/{org_id}/metadata", response_model=OrgMetadata)(
        get_platform_org_metadata
    )
    app.post(
        "/api/platform/orgs/{org_id}/users/{user_id}/deactivate",
        response_model=PlatformUserSummary,
    )(post_platform_org_user_deactivate)
    app.post(
        "/api/platform/orgs/{org_id}/users/{user_id}/reactivate",
        response_model=PlatformUserSummary,
    )(post_platform_org_user_reactivate)
    app.post(
        "/api/platform/orgs/{org_id}/users/{user_id}/password-reset",
        status_code=202,
        response_model=None,
    )(post_platform_org_user_password_reset)
    app.post(
        "/api/platform/orgs/{org_id}/users/{user_id}/invitation",
        response_model=InvitationSummary,
    )(post_platform_org_user_invitation)
    app.get("/api/platform/diagnostics", response_model=PlatformDiagnosticsResponse)(
        get_platform_diagnostics
    )
    app.post("/api/chats", status_code=201, response_model=ChatSummary)(post_chat)
    app.get("/api/chats", response_model=ChatListResponse)(get_chats)
    app.get("/api/chats/{chat_id}", response_model=ChatDetailResponse)(get_chat_detail)
    app.patch("/api/chats/{chat_id}", response_model=ChatSummary)(patch_chat)
    app.delete("/api/chats/{chat_id}", status_code=204, response_model=None)(delete_chat)
    app.post(
        "/api/chats/{chat_id}/messages",
        response_model=ChatResponse,
        responses=_EVENT_STREAM_RESPONSES,
    )(post_chat_message)
    app.post("/api/chats/{chat_id}/stop", response_model=ChatStopResponse)(post_chat_stop)
    app.post("/api/chats/{chat_id}/attachments", status_code=201, response_model=AttachmentSummary)(
        post_chat_attachment
    )
    app.get("/api/attachments/{attachment_id}", response_model=AttachmentSummary)(
        get_attachment_metadata
    )
    app.get("/api/attachments/{attachment_id}/content", response_model=None)(get_attachment_content)
    app.post("/api/message", response_model=ChatResponse)(post_message)
    app.post(
        "/api/confirm/{confirmation_id}",
        response_model=ChatResponse,
        responses=_EVENT_STREAM_RESPONSES,
    )(post_confirm)
    app.get("/api/me/settings", response_model=UserSettingsResponse)(get_my_settings)
    app.patch("/api/me/settings", response_model=UserSettingsResponse)(patch_my_settings)
    app.post("/api/me/settings/reset", response_model=UserSettingsResponse)(reset_my_settings)
    app.get("/api/org/settings", response_model=OrgSettingsResponse)(get_org_settings)
    app.patch("/api/org/settings", response_model=OrgSettingsResponse)(patch_org_settings)
    app.get("/api/platform/settings", response_model=PlatformSettingsResponse)(
        get_platform_settings
    )
    app.patch("/api/platform/settings", response_model=PlatformSettingsResponse)(
        patch_platform_settings
    )
    app.get("/api/org/permissions", response_model=PermissionsResponse)(get_org_permission_matrix)
    app.patch("/api/org/permissions", response_model=PermissionsResponse)(
        patch_org_permission_matrix
    )
    app.get("/api/org/critical-permissions", response_model=CriticalPermissionsResponse)(
        get_org_critical_permissions
    )
    app.patch(
        "/api/org/critical-permissions/{tool}/{action}",
        response_model=CriticalPermissionState,
    )(patch_org_critical_permission)
    app.delete(
        "/api/org/critical-permissions/{tool}/{action}/pending",
        response_model=CriticalPermissionState,
    )(cancel_org_critical_permission_pending)
    app.get("/api/permissions/summary", response_model=PermissionsSummaryResponse)(
        get_permissions_summary
    )

    # OAuth routes.
    app.get("/api/oauth/google/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_google_authorize
    )
    app.get("/api/oauth/microsoft/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_microsoft_authorize
    )
    app.get("/api/oauth/callback")(oauth_callback)  # public, state-checked
    app.get("/api/oauth/google/status", response_model=OAuthConnectionStatus)(oauth_google_status)
    app.get("/api/oauth/microsoft/status", response_model=OAuthConnectionStatus)(
        oauth_microsoft_status
    )
    app.delete("/api/oauth/google")(oauth_google_disconnect)
    app.delete("/api/oauth/microsoft")(oauth_microsoft_disconnect)

    # --- Static files (MUST be last so API routes take priority) ---
    # Resolve the PWA static directory. Checked in order:
    #   1. ADMINO_STATIC_DIR env var (explicit override, e.g. for tests)
    #   2. /app/static (Docker image layout — copied by Dockerfile)
    #   3. <repo>/static (dev layout: src/admino/server.py -> repo root -> static)
    # Mount only if a directory is found; skip silently in tests. A missing
    # client route (e.g. /login, /reset-password) is answered with index.html
    # for the PWA's router; /api and /health paths never fall back.
    static_dir: PathLib | None = None
    env_static = os.environ.get("ADMINO_STATIC_DIR")
    candidates: list[PathLib] = []
    if env_static:
        candidates.append(PathLib(env_static))
    candidates.append(PathLib("/app/static"))
    candidates.append(PathLib(__file__).parent.parent.parent / "static")
    for candidate in candidates:
        if candidate.is_dir():
            static_dir = candidate
            break
    if static_dir is not None:
        app.mount("/", _SpaStaticFiles(directory=str(static_dir), html=True), name="static")

    return app
