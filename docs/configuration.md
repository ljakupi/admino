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
- [Accounts and sessions](#accounts-and-sessions)
- [Email (SMTP)](#email-smtp)
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

![Settings → Agent provider control](screenshots/settings-agent.png)

<sub>Settings → Agent — pick the provider and its model.</sub>

**Switching providers:**

- In the UI: **Settings → Agent**, pick the provider.
- Or set `LLM_PROVIDER` in the environment (overrides `config.yaml`).
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
up to 200,000 input tokens and support function calling. **Settings → Agent** lists the
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
if the model is already provisioned. Then pick **vLLM** in **Settings → Agent**.

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
| `server` | Bind `host` / `port` for the ASGI server. |
| `database` | Connection pool sizing (`min_pool_size`, `max_pool_size`). |
| `llm` | `provider`, request `timeout_s`, and the cloud `*_model` IDs. |
| `limits` | Guardrails: max tool calls per message, pending confirmations, message length, context window (the system prompt and your latest message are always sent). |
| `egress` | `allowed_hosts` — the single source of truth for the outbound whitelist. |

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
  the platform's policy, with the same defaults. Your browser only holds a random token in
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
  and the OAuth callback. A deactivated account, or an account whose organization is
  deactivated or pending deletion, is refused on its next request, even with a session
  that's still open.
- **A failed login** always answers "Invalid email or password", whatever the reason.
  Successful and failed logins are recorded in the audit log, without the email address.
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
not log request paths either.

| Variable | Default | Notes |
| --- | --- | --- |
| `COOKIE_SECURE` | `true` | Marks the session cookie `Secure`, so browsers only send it over HTTPS (and to `http://localhost`). Set it to `false` only when you open admino over plain HTTP from another address, such as a phone on your LAN. |
| `ADMINO_PUBLIC_URL` | `http://localhost:8000` | The address users open admino at, such as `https://admino.example.ch` (no path). Password reset links and invitation links are built from it, never from the request's `Host` header. It must use `https`; plain `http` is only allowed for `localhost`, `127.0.0.1` and `[::1]`. **Production deployments must set it**, otherwise reset and invitation emails point at localhost. An invalid value stops admino at startup. Overrides `server.public_url` in `config.yaml`. |

> The login page, the pages for asking for a reset link and choosing the new password, and
> the page for accepting an invitation are still being added. Until they ship, the API
> answers `401` to every call that has no session.

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

## Data & storage

PostgreSQL holds `settings`, `permissions`, `memory` notes, `oauth_tokens`, the
`audit_events` audit trail, and the `email_outbox` of queued transactional email.

- **OAuth tokens** are stored as **encrypted ciphertext only**. The Fernet encryption key
  lives in the `OAUTH_ENCRYPTION_KEY` environment variable and is **never** persisted to
  the database. Lose the key and stored tokens are unrecoverable; rotating it requires
  re-running the [OAuth consent flow](getting-started.md#connect-your-accounts).
- **The audit log** is the **append-only `audit_events` table**. Every tool call adds one
  row with the tool, the action, the permission decision, success and duration. Arguments,
  tool output and message text are never stored. Rows are kept for 12 months, and a daily
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

For the full picture of how egress containment works — the firewall, the root→non-root
privilege drop, capabilities, and known limitations — read the
**[Security Model](SECURITY.md)**.

---

See also: **[Getting Started](getting-started.md)** · **[Permissions](permissions.md)** ·
[← Docs home](README.md)
