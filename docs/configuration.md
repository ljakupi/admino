# Configuration

admino is configured by two things:

- **`config/config.yaml`** — non-secret application settings, validated by Pydantic at
  startup. The agent refuses to start on invalid config with a clear error.
- **Environment variables** — **all secrets** (API keys, OAuth client secrets, the
  encryption key, the auth token) and a few runtime overrides. Documented inline in
  [`.env.example`](../.env.example).

> **Secrets are never read from `config.yaml`.** They come from the environment only, and
> are never written to disk in plaintext.

- [LLM providers](#llm-providers)
- [Infomaniak AI Services (default)](#infomaniak-ai-services-default)
- [Local vLLM (CPU container)](#local-vllm-cpu-container)
- [`config.yaml` reference](#configyaml-reference)
- [Settings: mine, organization, platform](#settings-mine-organization-platform)
- [Accounts and sessions](#accounts-and-sessions)
- [Email (SMTP)](#email-smtp)
- [Production deployment (TLS reverse proxy)](#production-deployment-tls-reverse-proxy)
- [Data & storage](#data--storage)
- [Egress whitelist](#egress-whitelist)

## LLM providers

**Infomaniak AI Services is the default provider**: an OpenAI-compatible API hosted in
Switzerland. A local vLLM container and two cloud providers are opt-in.

| Provider | Status | Needs |
| --- | --- | --- |
| **Infomaniak** | **default** · cloud, processed in Switzerland | `INFOMANIAK_API_TOKEN` (`ai-tools` scope). See below. |
| **vLLM** | opt-in · local CPU container (cross-platform) | `make start-local`. See [Local vLLM](#local-vllm-cpu-container). |
| **Claude (Anthropic)** | opt-in cloud | `ANTHROPIC_API_KEY` in the environment. |
| **OpenAI** | opt-in cloud | `OPENAI_API_KEY` in the environment, and `api.openai.com` in the egress whitelist. |

The active provider processes your messages and tool results. Everything else (audit
log, memory, documents) stays on the server that runs admino. API keys and tokens live in
environment variables on the server only: they're never written to `config.yaml`, never
logged, and never sent to the browser.

**When something is missing, admino still boots.** A missing API key or model, a rejected
key, a rate limit or an unreachable provider never stops startup or a provider switch.
The chat replies with what's wrong and what to do (for example "Infomaniak isn't
configured; set INFOMANIAK_API_TOKEN on the server"). Unexpected internal errors get a
generic "try again" reply and are logged without message content.

**Switching providers.** The provider is a platform setting: it applies to every
organization, and only the Super Admin can change it.

- Set `llm.provider` in `config.yaml`, or `LLM_PROVIDER` in the environment (it overrides
  `config.yaml`), and restart. `config.yaml`'s `llm` section is applied again at every
  start.
- Or, as the Super Admin, `PATCH /api/platform/settings` with e.g.
  `{"llm": {"provider": "vllm"}}` (see [Settings](#settings-mine-organization-platform)).
  The switch applies at once, until the next restart. There's no page for it yet; the
  Platform console adds one.
- Model IDs live in `config.yaml` under `llm` (`infomaniak_model`, `vllm_model`,
  `anthropic_model`, `openai_model`); all stay set so switching needs no model edit. The
  API key still comes from the environment.
- Point the OpenAI provider at any OpenAI-compatible server with `OPENAI_BASE_URL`.

## Infomaniak AI Services (default)

admino talks to Infomaniak's OpenAI-compatible endpoint
`https://api.infomaniak.com/2/ai/{product_id}/openai/v1` (`/chat/completions`, `/models`).

| Variable | Required | Notes |
| --- | --- | --- |
| `INFOMANIAK_API_TOKEN` | yes | Create it in the Infomaniak Manager → **API tokens** with the **`ai-tools`** scope. Sent as `Authorization: Bearer …` to `api.infomaniak.com` only. |
| `INFOMANIAK_PRODUCT_ID` | no | Your AI Tools product ID (a number). When unset, admino discovers it at startup with `GET https://api.infomaniak.com/1/ai`. If the token sees several products, the startup log and the chat ask you to set it. |

**Models.** The default is `Qwen/Qwen3.5-397B-A17B-FP8` (`llm.infomaniak_model`), with
`Qwen/Qwen3.5-122B-A10B-FP8` as the smaller alternative. Both take text and images, accept
up to 200,000 input tokens and support function calling. As the Super Admin, `GET /api/platform/settings` lists the
models your product offers (`GET …/openai/v1/models`) and shows whether the token is
configured.

**Privacy.** Processing happens in Infomaniak's data centers in Switzerland. Infomaniak
states that queries are neither recorded nor used to train models or improve its
services. admino sends no account identifiers: the OpenAI `user` field isn't set, and no
names or email addresses are added to prompts.

**Reasoning ("thinking").** Qwen3.5 thinks before answering by default. admino turns this
off with `reasoning_effort: "none"`, the switch Infomaniak documents for its chat API. As a
safety net it never reads the `reasoning_content` / `reasoning` fields and strips
`<think>…</think>` blocks from answers, including across streamed chunks, so reasoning text
never reaches the chat.

**Errors.** A rejected token (401/403), a rate limit (429) and temporary failures (5xx,
timeouts) come back as short chat messages. Response bodies are never logged. Retries are
left to the upcoming LLM gateway. Billing is per token: set a spending limit on the
product in the Infomaniak Manager.

## Local vLLM (CPU container)

admino ships `vllm/vllm-openai-cpu:latest` — a **multi-arch** image (`linux/arm64` +
`linux/amd64`). Docker auto-pulls the right variant on Apple Silicon and x86-64 Linux.
The container exposes an OpenAI-compatible API on port 8000 and is attached to the
`internal` Docker bridge only — **zero external network access** at runtime.

**Default model:** `Qwen/Qwen3-4B-Instruct-2507` — a small, strong tool-caller (~8 GB
FP16). NVIDIA GPU serving is tracked in
[#132](https://github.com/ljakupi/admino/issues/132) (swap the CPU image → CUDA image +
add a GPU reservation).

**Trade-offs to be aware of:**

- CPU inference is slow: expect a few tokens per second. `Qwen/Qwen3-1.7B-Instruct-2507`
  is snappier if throughput matters.
- Docker Desktop must have **~12–16 GB RAM allocated** (Settings → Resources → Memory).
  The default 8 GB is not enough for a 4B FP16 model.
- FP16 only (no 4-bit quant in the CPU image).

### Daily workflow

```bash
make start-local # provision (first run) + bring up postgres + agent + vllm together
make vllm-pull   # optional: pre-download model weights (~8 GB) into the Docker volume
                 # Set HF_TOKEN in the environment first if the model repo is gated.
make vllm-down   # stop just the vllm container (agent + postgres keep running)
```

`make start` / `make docker-up` no longer start vllm. `make start-local` is the
one-command path for the local model: it checks the volume first and skips the download
if the model is already provisioned. Then switch the provider to `vllm` (see
[Switching providers](#llm-providers)).

### Override the model or endpoint

| Variable | Default (from `config.yaml`) | Notes |
| --- | --- | --- |
| `VLLM_MODEL` | `Qwen/Qwen3-4B-Instruct-2507` | Any HuggingFace model the CPU image supports. `vllm-pull` and the vllm container both honor this. |
| `VLLM_BASE_URL` | `http://vllm:8000/v1` | The agent reaches the vllm service over the internal Docker bridge. Only change this if you run vllm outside of docker-compose. |
| `VLLM_MAX_MODEL_LEN` | `8192` | Maximum sequence length in tokens. Raise for longer context if you have enough RAM. |
| `VLLM_IMAGE` | `vllm/vllm-openai-cpu:latest` | Swap for the CUDA image to use NVIDIA GPU serving (see issue #132). |
| `HF_TOKEN` | *(unset)* | Only for `make vllm-pull` when the model repo is gated. Never read at serve time. |

## `config.yaml` reference

The shipped [`config/config.yaml`](../config/config.yaml) is fully commented. The sections:

| Section | What it controls |
| --- | --- |
| `server` | Bind `host` / `port` for the ASGI server, the session cookie's `cookie_secure` flag, the `public_url` users open admino at, and the `trusted_proxies` whose `X-Forwarded-*` headers are believed (see [Production deployment](#production-deployment-tls-reverse-proxy)). |
| `database` | Connection pool sizing (`min_pool_size`, `max_pool_size`). |
| `llm` | `provider`, request `timeout_s`, and the cloud `*_model` IDs. The provider and model IDs are also [platform settings](#settings-mine-organization-platform); this section is applied again at every start. |
| `limits` | Guardrails: max tool calls per message, pending confirmations, message length, context window (the system prompt and your latest message are always sent). They seed the [platform settings](#settings-mine-organization-platform) on the first start; later edits here don't apply. Change them with `PATCH /api/platform/settings` instead. |
| `egress` | `allowed_hosts` — the single source of truth for the outbound whitelist. |
| `log_level` | Top-level key: `DEBUG`, `INFO` (default), `WARNING`, `ERROR` or `CRITICAL`. The `LOG_LEVEL` env var overrides it. |
| `log_format` | Top-level key: `text` (default) or `json`, one JSON object per line (`ts`, `level`, `logger`, `message`, `request_id`) for a log collector. The `LOG_FORMAT` env var overrides it (`text` or `json`, any case; another value is ignored with a warning). Logs never hold content, see [Logs and error tracking](SECURITY.md#logs-and-error-tracking). |

## Settings: mine, organization, platform

Settings have three scopes. Each has an owner and its own route; any other role gets
`403`.

| Scope | Who changes it | Route | What it holds |
| --- | --- | --- | --- |
| **Mine** | every account | `GET` / `PATCH /api/me/settings`, `POST /api/me/settings/reset` | Theme, tool-approval pings and task-done pings. The **Settings** page shows only these. |
| **Organization** | Org Admin | `GET` / `PATCH /api/org/settings` | Which tool services the agent may use: Gmail, Google Calendar, Google Drive, Outlook, Outlook Calendar, OneDrive and memory. Org Admins switch them under **Organization → Services**. The response also carries the organization's data residency policy (`data_residency`, read-only here). |
| **Platform** | Super Admin | `GET` / `PATCH /api/platform/settings` | The LLM provider and a model per provider, the platform limits, and the [platform defaults](#platform-defaults): file limits, retention, and security. |

- The UI and response languages belong to your account, not to these settings.
- `POST /api/me/settings/reset` resets only your own settings to the defaults: light theme,
  tool-approval pings on, task-done pings off. Your connected accounts and languages, and the
  organization and platform settings, stay as they are.
- Organization and platform changes are recorded in the audit log: which fields changed,
  a tool's old and new on/off state, and a platform number's old and new value. Model names
  are never recorded.
- A tool service an organization switches off is off for that organization only. Each
  chat run reads its own organization's services, so other organizations aren't affected.
- When the organization's data residency policy is on, the Google and Microsoft services
  are off whatever their switch says, and **Organization → Services** shows them locked.
  Their stored switches are kept for when residency is off.
- The tool permission matrix and critical promotions are per organization too. See
  [Permissions → Per organization](permissions.md#per-organization).
- Upgrading from a version with the single `settings` table drops it: everyone starts from
  the defaults (light theme, tool-approval pings on, task-done pings off, every tool
  service on), and the platform settings start from `config.yaml`.

### Platform defaults

`PATCH /api/platform/settings` takes any of these sections. Each field is optional, and
the response holds every section after the change.

| Section | Field | Default | Range | Used by |
| --- | --- | --- | --- | --- |
| `limits` | `max_tool_calls_per_message` | from `config.yaml` (10) | 1–100 | every message |
| `limits` | `max_pending_confirmations` | from `config.yaml` (3) | 1–50 | — |
| `limits` | `confirmation_timeout_s` | from `config.yaml` (300) | 10–3600 | every message |
| `limits` | `max_message_length` | from `config.yaml` (4000) | 1–100,000 | every message |
| `limits` | `max_context_messages` | from `config.yaml` (20) | 1–200 | every message |
| `files` | `max_file_size_mb` | 50 | 1–500 | attachments (later release) |
| `files` | `max_files_per_message` | 10 | 1–50 | attachments (later release) |
| `files` | `max_pages_per_file` | 100 | 1–1000 | attachments (later release) |
| `files` | `render_dpi` | 150 | 72–300 | page images (later release) |
| `retention` | `trash_min_days`, `trash_max_days` | 0, 90 | 0–90, min ≤ max | the bounds of each organization's trash retention (later release) |
| `retention` | `audit_months` | 12 | 6–84 | the daily audit purge |
| `retention` | `org_deletion_grace_days` | 30 | 7–90 | the next organization deletion you schedule |
| `security` | `rate_limit_per_minute` | 20 | 1–600 | per-user request limit (later release) |
| `security` | `lockout_after_failures` | 10 | 3–100 | brute-force protection |
| `security` | `lockout_window_minutes` | 15 | 1–1440 | brute-force protection |
| `security` | `lockout_minutes` | 15 | 1–1440 | brute-force protection |
| `security` | `session_idle_timeout_minutes` | 60 | 15–480 | Super Admin sessions |
| `security` | `session_max_lifetime_hours` | 12 | 1–72 | Super Admin sessions |

- A change applies without a restart: the next message, login attempt, deletion schedule
  or audit purge uses the new value.
- **The Super Admin session policy applies to open sessions too.** Every open Super Admin
  session takes the new idle timeout, and its end moves to its start plus the new
  lifetime. A session older than a shortened lifetime ends at once, your own included.
- A deletion that's already scheduled keeps its date.
- A lock that's already set keeps its end. Lowering `lockout_window_minutes` lets failed
  attempts older than the new window stop counting at once, so don't lower it during an
  attack; raise `lockout_minutes` or lower `lockout_after_failures` instead.
- A value out of range answers `422`. A trash minimum above the maximum, after merging
  with the stored values, answers `400`. Nothing is changed in either case.

## Accounts and sessions

admino has user accounts: you log in with your email address and password, and the
server keeps your session.

There's no public sign-up. The first account, a Super Admin, is created on the server with
`make create-superadmin` (see
[Create the first Super Admin](getting-started.md#5-create-the-first-super-admin)).

- **Passwords** are hashed with **Argon2id** (19 MiB of memory, 2 iterations, 1 lane). When
  these settings change, your hash is upgraded at your next login. A password has 12 to 128
  characters, isn't your email address, and isn't one of the 100,000 most common passwords.
  That list is bundled with admino, so nothing is sent anywhere to check a password.
- **Sessions** end after 60 minutes without activity, and after 12 hours at most, even
  when you stay active. That's your organization's session policy; a later release lets
  Org Admins change it (15 to 480 minutes idle, 1 to 72 hours at most). Super Admins get
  the platform's session policy, a [platform default](#platform-defaults) with the same
  defaults. Your browser only holds a random token in
  the `admino_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure`), and the database
  only stores its SHA-256 hash.
- **Ending a session** deletes it at once, and its cookie stops working on the next
  request: logging out, ending one of your sessions, an Org Admin's forced logout, and a
  password reset (which ends all of them). Sessions that expired or went idle are deleted
  every hour.
- **Your sessions**: `GET /api/me/sessions` lists the sessions you're logged in with (when
  each started and was last used, until when it can last, its IP address and browser, and
  which one is the current one). `DELETE /api/me/sessions/{id}` ends one of them, for
  example a browser you forgot to log out of. Ending a session is recorded in the audit
  log.
- **Forced logout**: an Org Admin can log a user of their organization out of every device
  with `POST /api/org/users/{id}/logout`. It's recorded in the audit log, with the number
  of sessions that ended.
- **Every API route needs a session**, except `/health`, the login endpoint, the two
  password reset endpoints (`POST /api/auth/password-reset` and
  `POST /api/auth/password-reset/confirm`), the two invitation link endpoints
  (`GET /api/auth/invitations/{token}` and `POST /api/auth/invitations/{token}/accept`)
  and the OAuth callback. The callback completes a connection only in the browser that
  started it and only while the session that started it is still open. A deactivated
  account, or an account whose organization is deactivated or pending deletion, is refused
  on its next request, even with a session that's still open.
- **`/health` only says up or degraded.** It answers `{"status": "ok"}`, or `503`
  `{"status": "degraded"}` when the database is unreachable, and is rate-limited per IP
  address. The active LLM provider, the model and whether the provider is reachable are
  on `GET /api/platform/diagnostics`, for Super Admins only. Every response carries an
  `X-Request-ID` header that matches the request's log lines.
- **A failed login** always answers "Invalid email or password", whatever the reason.
  Successful and failed logins are recorded in the audit log, without the email address.
- **Brute-force protection** counts failed logins per account and per IP address, and
  the counts survive a restart. After 3 failures in 15 minutes, each further attempt
  waits before the password is checked: 1, 2, 4, then 8 seconds. After 10 failures in
  15 minutes, the account or the IP address is locked for 15 minutes. The failure count,
  the window and the lock duration are [platform defaults](#platform-defaults); the
  numbers here are their defaults. A locked login
  gets the same "Invalid email or password" as a wrong password, even with the right
  password, and the lock expires on its own. Every lockout is recorded in the audit log
  (`login.lockout`). An address that was never registered is counted the same way, so
  the protection doesn't reveal which accounts exist.
- **Password reset and invitation links share the IP counter.** An unusable link counts
  as a failed attempt from that IP address. While the address is locked, confirming a
  reset, opening an invitation link, accepting an invitation and asking for a reset
  link answer `429` "Too many attempts. Try again later." Asking for a reset link never
  counts as a failure.
- **Cross-site requests** that change something (`POST`, `PATCH`, `DELETE`) are refused
  with `403`.
- **Rate limits** apply per user, and per IP address for the login, the password reset
  and the invitation link endpoints (an IP address gets one reset email a minute, after
  the first three). An IP address that keeps sending unknown session cookies is refused
  with `429` for a while.

**Forgot your password?** Ask for a reset link with your email address. If the account
exists and may log in, admino emails a link to `/reset-password` that works once, for 30
minutes. Asking again replaces the older link, so only the newest one works. When you set
the new password, it has to follow the password rules above, and every session of the
account ends, so all your devices are logged out, including the browser you reset from.
The request always answers `202` the same way, whether the address exists or not, so
nobody can use it to find out which accounts exist. Reset requests and completed resets
are recorded in the audit log, without the email address. Only a hash of the link's token
is stored.

**Invitations.** An Org Admin invites people into their organization with an email
address and a role (Org Admin, Editor or Viewer): `POST /api/org/invitations`. The
address can't belong to any account on the platform yet, in any capitalization. admino
emails the invitee a link to `/accept-invitation` that works once, for 72 hours. Opening
it shows the organization, the role and the email address; accepting it with a name and a
password (which follows the password rules above) activates the account and logs the
invitee in. The email goes out in the inviting admin's language, which also becomes the
new account's language. A pending invitation takes a seat, even after its link expired,
until it's revoked or accepted, so an organization with no free seat can't invite anyone
else. Org Admins list the pending invitations (`GET /api/org/invitations`, expired ones
marked), revoke one (`DELETE /api/org/invitations/{id}`, which frees the address and the
seat) or send it again with a new link (`POST /api/org/invitations/{id}/resend`, the old
link stops working, an email with it that hasn't gone out yet is cancelled, and the 72
hours start over). Sending, revoking, resending and accepting are recorded in the audit
log, without the email address. Only a hash of the link's token is stored.

A send refused because the address is already taken, or because there's no free seat,
answers `409` and is recorded in the audit log too (without the address). Refused sends
have their own, tighter limit per Org Admin: after five, only one a minute is allowed, and
further sends get `429`. This keeps anyone from quickly checking which addresses have an
account elsewhere on the platform. The link's token is part of the URL path of the two
link endpoints, so admino doesn't write access logs; a reverse proxy in front of it must
not log request paths either. The bundled Caddy proxy doesn't (see
[Production deployment](#production-deployment-tls-reverse-proxy)).

| Variable | Default | Notes |
| --- | --- | --- |
| `COOKIE_SECURE` | `true` | Marks the session cookie `Secure`, so browsers only send it over HTTPS (and to `http://localhost`). `false` is a **development-only** setting, for opening a laptop install over plain HTTP from another address, such as a phone on your LAN. admino refuses to start with `false` when `ADMINO_PUBLIC_URL` is `https`, and the production profile always sets `true`. |
| `ADMINO_PUBLIC_URL` | `http://localhost:8000` | The address users open admino at, such as `https://admino.example.ch` (no path). Password reset links and invitation links are built from it, never from the request's `Host` header. It must use `https`; plain `http` is only allowed for `localhost`, `127.0.0.1` and `[::1]`. **Production deployments must set it**, otherwise reset and invitation emails point at localhost (the production profile sets it to `https://ADMINO_DOMAIN`). It's also the only origin CORS allows. An invalid value stops admino at startup. Overrides `server.public_url` in `config.yaml`. |
| `ADMINO_TRUSTED_PROXIES` | *(empty)* | Comma-separated IP addresses or CIDR ranges of the reverse proxies in front of admino. Only a request that arrives from one of them has its `X-Forwarded-For` (the client's IP, used by per-IP rate limits and audit events) and `X-Forwarded-Proto` believed; every other peer's are ignored. Empty trusts nobody. A range covering every address (`0.0.0.0/0`, `::/0`) and invalid entries stop admino at startup. The production profile sets Caddy's address. Overrides `server.trusted_proxies` in `config.yaml`. |

**In the app.** The PWA has a **Log in** page, a **Forgot password** page that asks for
the reset link, a **Reset password** page that the emailed link opens, and an **Accept
invitation** page where the invitee sets their name and password. The link's token stays
in the part of the URL after `#`, which the browser never sends to the server, and the page
removes it from the address bar as soon as it has read it. The password fields list the
password rules, and errors stay as generic as the server's answers ("Invalid email or
password", "This reset link is invalid or has expired."). Before you log in, the pages
follow your browser's language (German, French or English, otherwise English); after you
log in, they follow your account's language.

When a session ends (it expired, went idle, or was ended elsewhere), the next request
answers `401`. The app then says your session has expired and opens the login page. After
you log in again, it takes you back to the page you were on. The server serves the app for
these pages' addresses too, so the emailed links work in a browser that has never opened
admino before.

What you see depends on your role:

| Role | Pages |
| --- | --- |
| Org Admin | Chat, Tools, Organization, Settings |
| Editor | Chat, Tools, Permissions (read-only), Settings |
| Viewer | Chat (read-only: projects shared with you, with no message box), Permissions (read-only) and Settings |
| Super Admin | Platform only (no chat) |

The Organization page holds the organization's services (which tools the agent may use),
tool permissions and critical permissions. Later releases add users, settings and more.
The Tools page is **My connections**: each user connects their own Google and Microsoft
accounts there (see [Tools → Authentication](tools.md#authentication)). The Permissions page shows Editors and Viewers
what the agent may do in their organization. The Platform page is a placeholder that a later
release fills in. The server checks every request on its own, so a hidden page's API still
refuses a role that isn't allowed to use it.

## Organizations (Super Admin)

The Super Admin creates organizations, sets their plan limits, deactivates and deletes
them, and sets their data residency policy. These routes are for the Super Admin only
(`403` for everyone else), and they return organization metadata only, never content.
Every change is recorded in the organization's own audit log, so its Org Admins see what
the Super Admin did.

- **Create**: `POST /api/platform/orgs` with `name`, `primary_admin_email`, `seats`,
  `monthly_budget_chf`, `storage_quota` (in bytes) and optionally `status` (`active` by
  default, or `deactivated`). admino creates the organization and emails its first Org
  Admin an [invitation](#accounts-and-sessions) in the Super Admin's language. An address
  that already has an account answers `409` and creates nothing. On the server, the same
  works from the command line (see
  [Create an organization](getting-started.md#6-create-an-organization)).
- **List**: `GET /api/platform/orgs` returns every organization with its status, plan
  limits, residency policy and deletion dates.
- **Plan limits**: `PATCH /api/platform/orgs/{id}/limits` with any of `seats`,
  `monthly_budget_chf` and `storage_quota`. Lowering the seats below the seats in use is
  allowed; it only stops new invitations until seats are free again.
- **Deactivate and reactivate**: `POST /api/platform/orgs/{id}/deactivate` and
  `POST /api/platform/orgs/{id}/reactivate`. Deactivating logs every member out at once,
  and nobody of that organization can log in or use a link until it's reactivated. Its
  data is kept.
- **Delete, in two steps**:
  1. `POST /api/platform/orgs/{id}/deletion` schedules the deletion. The organization is
     deactivated (everyone is logged out), its data is purged after the grace period
     (**30 days** by default, a [platform default](#platform-defaults)), and its
     active Org Admins get an email with the date.
  2. Until the purge has run, `DELETE /api/platform/orgs/{id}/deletion` cancels it. The
     organization stays deactivated; reactivate it to let its members back in.

  A background job checks every hour (and at startup) for organizations past their date
  and **irreversibly** deletes everything they hold: their users with their sessions,
  invitations and queued email, their audit log, the organization itself, and its files on
  disk. What stays is the platform's record of the deletion: an `org.purge` audit event
  with the organization's ID and counts, no names.

  The database enforces the grace period too: a deletion is always open for at least
  7 days and its dates can't change while it's pending, so nothing can purge an
  organization, or its audit log, sooner (see
  [Security Model → Database roles](SECURITY.md#database-roles)).
- **Data residency**: `PATCH /api/platform/orgs/{id}/residency` with `{"enabled": true}`
  or `false`. New organizations start with it on. The change is recorded in the
  organization's audit log, where its Org Admins see it. While it's on, the organization's
  Google and Microsoft tools are disabled and its members can't connect those accounts;
  connections made before are kept but inactive until it's turned off.

An organization's status can only move this way: active ⇄ deactivated, active or
deactivated → pending deletion, pending deletion → deactivated (cancelled). Anything else,
and changing limits or residency while a deletion is pending, answers `409`.

## Email (SMTP)

admino sends transactional email through **one SMTP account for the whole platform**:
invitations, password resets, account activated/deactivated notices, budget alerts,
model deprecation notices and scheduled org deletion notices, for every organization.
Organizations don't configure their own mail server.

We recommend a **Swiss-based provider** so mail stays in Switzerland, for example
**Infomaniak Mail** (`mail.infomaniak.com`, port 587 or 465). Dev and production use the
same path, a real SMTP account, so use addresses you can receive when you test.

| Variable | Notes |
| --- | --- |
| `SMTP_HOST` | The server's hostname, e.g. `mail.infomaniak.com`. IP addresses and single-label names are refused. |
| `SMTP_PORT` | `587` (STARTTLS) or `465` (implicit TLS). Any other port is refused. |
| `SMTP_USERNAME` | The SMTP login, usually the full mailbox address. |
| `SMTP_PASSWORD` | Read from the environment only, never logged. |
| `SMTP_FROM` | The sender address. Use the mailbox address or one of its aliases; providers usually reject other senders. |

**TLS is required.** admino uses Python's standard `smtplib` with a verified default TLS
context: it checks the certificate and the hostname, and never falls back to plaintext.
If a server on 587 doesn't offer STARTTLS, the attempt fails and is retried.

**Outbox and retries.** Emails are written to the `email_outbox` table and sent by a
background task, so a slow or unreachable mail server never delays a request. A failed
attempt is retried with exponential backoff (1 minute, doubling up to 6 hours), up to 10
attempts, and then marked `failed`. Delivery is at-least-once: if admino stops right after
the server accepted a message but before recording it as sent, that message goes out
again.

**Languages and content.** Each email comes in German, French and English, in the
recipient's UI language, as plain text plus a minimal HTML part. Emails contain no org
content: no project, chat or file names and no message text. The only values are the
organization's display name, links and dates (UTC).

**Data minimization.** The one-time links in invitation and password-reset emails are
stored unencrypted in the outbox while a message waits for delivery, and they're cleared
once it's sent or has finally failed. Sent and failed
rows are deleted after 30 days. Application logs name outbox IDs only, never email
addresses.

**Without SMTP.** If any of the five variables is missing or invalid, admino still starts
and logs which variables to fix (names only, never values). Emails stay queued and go out
after SMTP is configured and admino restarts.

## Production deployment (TLS reverse proxy)

The production profile runs admino behind **[Caddy](https://caddyserver.com)**, which
terminates TLS with a Let's Encrypt certificate. It's defined in
[`docker-compose.prod.yml`](../docker-compose.prod.yml) and started with its own `make`
targets:

```bash
# .env: ADMINO_DOMAIN=admino.example.ch (plus the usual PG_PASSWORD, PG_APP_PASSWORD, INFOMANIAK_API_TOKEN, SMTP_*)
make docker-build-prod    # build the agent and caddy images
make start-prod           # postgres + migrate + agent + caddy
make docker-logs-prod     # follow logs
make docker-down-prod     # stop everything
```

Before the first start, point the domain's DNS `A` record at the server and open ports
**80** and **443** inbound. Caddy requests the certificate on its first start and renews it
on its own. Port 80 answers Let's Encrypt's challenge and redirects everything else to
HTTPS.

What the profile sets up:

- **HTTPS only.** Plain HTTP redirects to HTTPS, and every response carries
  `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HSTS). admino's own
  security headers (CSP, `X-Frame-Options`, and the rest) are passed through unchanged.
- **The agent publishes no port.** Caddy is the only service on the host's ports, and it
  reaches the agent over an internal network that postgres isn't on.
- **Real client IPs.** Caddy replaces any `X-Forwarded-For` a client sends with the
  client's address. The agent believes it only from Caddy's fixed address
  (`ADMINO_TRUSTED_PROXIES=172.31.0.10/32`), so per-IP rate limits and audit events see
  the real client, and no other peer can fake one.
- **Secure session cookie and one origin.** The profile sets `COOKIE_SECURE=true` and
  `ADMINO_PUBLIC_URL=https://ADMINO_DOMAIN`, overriding `.env`. Emailed links use that
  address, and CORS allows only that origin.
- **Proxy egress: Let's Encrypt only.** Caddy's container has its own firewall that allows
  only Let's Encrypt's ACME API (certificate issuance and renewal) and the agent. It then
  drops root and runs without any capabilities. See the [Security Model](SECURITY.md#the-tls-reverse-proxy-production-profile).
- **No request paths in logs.** Caddy keeps no access log, and the loggers that would
  print a request's path or query string are turned off: invitation and reset tokens are
  part of some URLs.
- **No local model, one process.** The profile never starts the `vllm` container, and the
  agent runs as a single uvicorn process in a single container. Pending confirmations and
  rate-limit counters live in that process's memory, so don't scale it out.

**Trying it on a laptop.** With `ADMINO_DOMAIN=localhost`, Caddy uses its own local
certificate authority instead of Let's Encrypt. Check it with curl, e.g.
`curl -k -I https://localhost` and `curl -I http://localhost`. A browser that opens
`https://localhost` may remember the HSTS header and from then on switch
`http://localhost` addresses to HTTPS, including the laptop profile on
`http://localhost:8000`. If that happens, delete the `localhost` entry (in Chrome:
`chrome://net-internals/#hsts`).

## Data & storage

PostgreSQL holds the `platform_settings`, `org_settings` and `user_settings`, each organization's `permissions`,
each user's `memory` notes and `oauth_tokens` (one row per user and provider), the
`audit_events` audit trail, and the `email_outbox` of queued transactional email.

- **Two database roles.** The app connects as `admino_app`, a non-superuser with
  per-table rights (`PG_APP_PASSWORD`). The owner `admino` (`PG_PASSWORD`) applies the
  migrations in the one-shot `migrate` service before the agent starts (`make migrate` in
  local dev), and the app never gets its password. The app refuses to start while
  migrations are pending. See [Security Model → Database roles](SECURITY.md#database-roles).

- **OAuth tokens** are stored as **encrypted ciphertext only**. The Fernet encryption key
  lives in the `OAUTH_ENCRYPTION_KEY` environment variable and is **never** persisted to
  the database. Lose the key and stored tokens are unrecoverable; after rotating it, every
  user reconnects their accounts on the Tools page (see
  [Connect your accounts](getting-started.md#connect-your-accounts)).
- **The audit log** is the **append-only `audit_events` table**. Every tool call adds one
  row with the tool, the action, the permission decision, success and duration. Arguments,
  tool output and message text are never stored. Rows are kept for 12 months by default
  (6 to 84, a [platform default](#platform-defaults)), and a daily
  job purges older ones. See [Permissions](permissions.md#append-only-audit-log).

## Egress whitelist

`egress.allowed_hosts` in `config.yaml` is the **single source of truth** for outbound
network access. In Docker mode, `entrypoint.sh` derives the container's `iptables` rules
from this list at startup; `main.py` also checks that the configured LLM provider's API
host is present. The provider hosts are `api.infomaniak.com` (default, included),
`api.anthropic.com` (included) and `api.openai.com` (uncomment it for OpenAI).

Those hosts are opened on port 443 only. The one exception is email: when `SMTP_HOST` and
`SMTP_PORT` are set, `entrypoint.sh` also opens exactly that host on that port (465 or
587). See [Email (SMTP)](#email-smtp).

In the production profile, the Caddy proxy has a separate whitelist with a single
external host: Let's Encrypt's ACME API (`acme-v02.api.letsencrypt.org`, port 443). See
[Production deployment](#production-deployment-tls-reverse-proxy).

For the full picture of how egress containment works — the firewall, the root→non-root
privilege drop, capabilities, and known limitations — read the
**[Security Model](SECURITY.md)**.

---

See also: **[Getting Started](getting-started.md)** · **[Permissions](permissions.md)** ·
[← Docs home](README.md)
