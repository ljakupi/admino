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
- [Chats](#chats)
- [Email (SMTP)](#email-smtp)
- [Production deployment (TLS reverse proxy)](#production-deployment-tls-reverse-proxy)
- [Performance](#performance)
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

The active provider processes your messages and tool results. Everything else (chats,
audit log, memory, documents) stays on the server that runs admino. API keys and tokens
live in environment variables on the server only: they're never written to `config.yaml`,
never logged, and never sent to the browser.

**When something is missing, admino still boots.** A missing API key or model, a rejected
key, a rate limit or an unreachable provider never stops startup or a provider switch.
The startup log names what to set (for example "the INFOMANIAK_API_TOKEN env var is not
set"), and the chat shows a short message in the user's language, such as "This AI model
isn't set up yet. Ask your administrator to configure it." See
[LLM errors and retries](#llm-errors-and-retries).

**Switching providers.** The provider is a platform setting: it applies to every
organization, and only the Super Admin can change it.

- Set `llm.provider` in `config.yaml`, or `LLM_PROVIDER` in the environment (it overrides
  `config.yaml`), and restart. `config.yaml`'s `llm` section is applied again at every
  start.
- Or, as the Super Admin, `PATCH /api/platform/settings` with e.g.
  `{"llm": {"provider": "vllm"}}` (see [Settings](#settings-mine-organization-platform)).
  The switch applies at once, until the next restart. In the PWA, use
  **Platform → Defaults → Model**: pick the provider and its model, then **Save**. A switch
  to Claude or OpenAI needs the [residency confirmation](#data-residency-and-the-provider).
- Model IDs live in `config.yaml` under `llm` (`infomaniak_model`, `vllm_model`,
  `anthropic_model`, `openai_model`); all stay set so switching needs no model edit. The
  API key still comes from the environment.
- Point the OpenAI provider at any OpenAI-compatible server with `OPENAI_BASE_URL`.

### Data residency and the provider

Infomaniak and the local vLLM container are the **Swiss providers**: Infomaniak processes
requests in Switzerland, and vLLM runs on your own server. Claude (Anthropic) and OpenAI
aren't.

- **Residency organizations stay on Swiss providers.** When an organization's
  [data residency policy](#organizations-super-admin) is on and the active provider isn't
  `infomaniak` or `vllm`, its chats make no LLM call at all: each message ends with the
  error code `residency_blocked`, and a tool call approved after such a switch doesn't
  run. Organizations without the policy keep chatting.
- **Switching to Claude or OpenAI needs a confirmation.** The Super Admin confirms how
  many organizations the switch affects: the PATCH carries `confirm_residency_orgs` equal
  to the current number of organizations with data residency on, of every status
  (`llm.residency_orgs` in `GET /api/platform/settings`). For example, with no such
  organization: `{"llm": {"provider": "anthropic"}, "confirm_residency_orgs": 0}`. A
  missing or wrong number answers `409`
  `{"detail": "…", "reason": "residency_confirmation", "residency_orgs": 3}` with the
  current number, and nothing changes: no setting is written, nothing is recorded, and
  the running provider stays. The number is counted again when the switch is written: if
  an organization's data residency changed in between, the answer is the same `409` with
  the new number.
  In **Platform → Defaults**, **Save** opens a confirmation dialog that names the number
  of organizations with data residency on and sends it for you when you confirm **Switch
  anyway**. If that number changed in the meantime, the dialog stays open with the new
  number, and your edits are kept.
- A switch to `infomaniak` or `vllm`, or a patch that keeps the provider, needs no
  confirmation; a given `confirm_residency_orgs` is ignored. `confirm_residency_orgs` is
  not a setting: a patch that gives only it answers `422`.
- Setting a non-Swiss provider in `config.yaml` (or `LLM_PROVIDER`) and restarting needs no
  confirmation, since only someone with access to the server can do it. The residency
  guard applies all the same.
- **No identifiers reach a provider.** admino never sends a user or organization ID, a
  name or an email address to any provider: no `user`, `metadata`, `safety_identifier`,
  `prompt_cache_key` or `store` field, and no `OpenAI-Organization` or `OpenAI-Project`
  header, even when `OPENAI_ORG_ID` or `OPENAI_PROJECT_ID` is set in the environment.

### LLM errors and retries

A chat reply that fails has `status: "error"`, and the `POST /api/chats/{id}/messages`,
`POST /api/message` and `POST /api/confirm/{id}` responses carry its `error_code` (a
[streamed reply](#streaming-replies) sends it as the `error` event's `code`):

| `error_code` | What happened |
| --- | --- |
| `not_configured` | The provider's API key or token is missing or was rejected (401/403), or the Infomaniak product can't be determined. |
| `missing_model` | No model is set for the provider, or the provider doesn't know it (404). |
| `provider_unavailable` | The provider can't be reached, or it failed (5xx). |
| `rate_limited` | The provider refused the request for its rate limit (429). |
| `timeout` | The provider didn't answer within `llm.timeout_s`, or a streamed reply didn't end within `llm.stream_deadline_s` (300 seconds by default, see the [`config.yaml` reference](#configyaml-reference)). |
| `context_too_long` | The conversation is longer than the model accepts (400/413). Start a new chat. |
| `residency_blocked` | The organization's data residency policy is on and the provider isn't Swiss (see [above](#data-residency-and-the-provider)). |
| `malformed_response` | The provider's reply couldn't be used: a tool call in it was malformed, or its data couldn't be read (see [Cleaning the model's output](#cleaning-the-models-output)). The whole reply is rejected. It isn't retried. |
| `rate_limit` | Not an LLM failure: you already have as many pending confirmations as allowed (`max_pending_confirmations`, a [platform default](#platform-defaults), 3 by default), so the action that needed one more wasn't run. The turn is stored (see [Chats](#chats)). Unlike `rate_limited`, it's admino's own limit, not the provider's. |

Any other failure has `error_code: null`. The chat shows the code's translated text
(English, German or French), or a generic "Something went wrong" text when there's no
code (and, in this release, for `rate_limit`). The response's `response` field holds an
English fallback text. **Provider text is never shown or logged**: no provider message,
response body or provider error code reaches a response or a log line. Errors are logged
by their type, HTTP status and code only.

**Retries.** A `timeout`, `provider_unavailable` or `rate_limited` failure is retried up to
`llm.max_retries` times (a [platform default](#platform-defaults): 2, from 0 to 5, `0`
turns retries off). Every other failure fails at once, `malformed_response` included.

- Before each retry admino waits the provider's `Retry-After` (or `retry-after-ms`) when
  it sends one, up to 10 seconds. A longer `Retry-After` isn't retried: the reply fails
  at once.
- Without one it waits an exponential backoff with jitter: up to 1, 2, 4, then 8 seconds
  (at most 8), each at least half of that.
- A retry sends the same request to the same provider and model, never to another one. A
  streamed reply is retried only before its first piece has arrived, and each attempt
  gets its own `llm.stream_deadline_s`.
- The provider SDKs' own retries are off, so each attempt is exactly one request and the
  limit above is the only one. Each retry logs one warning with its code, attempt number
  and delay.

### Cleaning the model's output

admino cleans every provider's output before the assistant uses it, in JSON and
streamed replies alike.

- **Text.** Control characters are removed: C0 controls except tab, line feed and
  carriage return, C1 controls, direction overrides and isolates, zero-width characters,
  the line and paragraph separators (U+2028, U+2029), the byte order mark and lone
  surrogates. An ANSI escape sequence loses its `ESC` (or `CSI`), so the rest (`[31m`,
  say) is plain text. A reply holds at most 65,536 characters (64 KiB), counted after
  cleaning. A reply cut there, or by the model's output cap
  (`llm.max_response_tokens`), ends at its last complete word.
- **Tool arguments.** Every string in a tool call's arguments, keys and values at any
  depth, is cleaned in two steps: each lone surrogate becomes U+FFFD (the replacement
  character), then the same characters as in text are removed. The argument limits (4
  levels deep, 32 keys, 2,048-character top-level strings, 16,384 characters of JSON)
  are checked before that.
- **Malformed tool calls.** When any tool call in a reply can't be used (its arguments
  don't decode, aren't a JSON object or exceed the limits, or its name isn't
  `tool.action`), the whole reply is rejected with `malformed_response`, even when its
  other tool calls were fine. So is a streamed reply with more than 128 tool calls or
  with a name or arguments too long, and a reply whose data can't be read. The error's
  message never quotes the reply, and no part of the reply is logged.

## Infomaniak AI Services (default)

admino talks to Infomaniak's OpenAI-compatible endpoint
`https://api.infomaniak.com/2/ai/{product_id}/openai/v1` (`/chat/completions`, `/models`).

| Variable | Required | Notes |
| --- | --- | --- |
| `INFOMANIAK_API_TOKEN` | yes | Create it in the Infomaniak Manager → **API tokens** with the **`ai-tools`** scope. Sent as `Authorization: Bearer …` to `api.infomaniak.com` only. |
| `INFOMANIAK_PRODUCT_ID` | no | Your AI Tools product ID (a number). When unset, admino discovers it at startup with `GET https://api.infomaniak.com/1/ai`. If the token sees several products, the startup log asks you to set it, and the chat says the model isn't set up yet. |

**Models.** The default is `Qwen/Qwen3.5-397B-A17B-FP8` (`llm.infomaniak_model`), with
`Qwen/Qwen3.5-122B-A10B-FP8` as the smaller alternative. Both take text and images, accept
up to 200,000 input tokens and support function calling. As the Super Admin, `GET /api/platform/settings` lists the
models your product offers (`GET …/openai/v1/models`) and shows whether the token is
configured. Their time to first token is measured with `make ttft`, and a rule based on
it decides which one is the default: see [Model latency](#model-latency).

**Privacy.** Processing happens in Infomaniak's data centers in Switzerland. Infomaniak
states that queries are neither recorded nor used to train models or improve its
services. admino sends no account identifiers: the OpenAI `user` field isn't set, and no
names or email addresses are added to prompts (see
[No identifiers reach a provider](#data-residency-and-the-provider)).

**Reasoning ("thinking").** Qwen3.5 thinks before answering by default. admino turns this
off with `reasoning_effort: "none"`, the switch Infomaniak documents for its chat API. As a
safety net it never reads the `reasoning_content` / `reasoning` fields and strips
`<think>…</think>` blocks from answers, including across streamed chunks, so reasoning text
never reaches the chat.

**Errors.** A rejected token (401/403), a rate limit (429) and temporary failures (5xx,
timeouts) come back as error codes the chat shows as short translated messages; rate
limits and temporary failures are retried first (see
[LLM errors and retries](#llm-errors-and-retries)). Response bodies are never logged.
Billing is per token, retries included: set a spending limit on the product in the
Infomaniak Manager.

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
| `llm` | `provider`, request `timeout_s`, `stream_deadline_s` (the most time one attempt of a streamed model call may take, opening the stream included: 300 seconds by default, above 0 up to 3600; past it the reply fails with `timeout`), the cloud `*_model` IDs, and the active model's capabilities: `max_input_tokens` (the most input tokens it accepts, default 200000, from 1000 to 2000000) and `image_input` (whether it accepts images, default `true`). The provider, the model IDs and the capabilities are also [platform settings](#platform-defaults); this section is applied again at every start. The retry limit isn't in `config.yaml`: it's a platform setting only. |
| `limits` | Guardrails: max tool calls per message, pending confirmations, message length, context window (how many of a chat's latest messages are sent to the model; the system prompt and your latest message are always sent, see [Chats](#chats)). They seed the [platform settings](#settings-mine-organization-platform) on the first start; later edits here don't apply. Change them with `PATCH /api/platform/settings` instead. |
| `egress` | `allowed_hosts` — the single source of truth for the outbound whitelist. |
| `log_level` | Top-level key: `DEBUG`, `INFO` (default), `WARNING`, `ERROR` or `CRITICAL`. The `LOG_LEVEL` env var overrides it. |
| `log_format` | Top-level key: `text` (default) or `json`, one JSON object per line (`ts`, `level`, `logger`, `message`, `request_id`) for a log collector. The `LOG_FORMAT` env var overrides it (`text` or `json`, any case; another value is ignored with a warning). Logs never hold content, see [Logs and error tracking](SECURITY.md#logs-and-error-tracking). |

## Settings: mine, organization, platform

Settings have three scopes. Each has an owner and its own route; any other role gets
`403`.

| Scope | Who changes it | Route | What it holds |
| --- | --- | --- | --- |
| **Mine** | every account | `GET` / `PATCH /api/me/settings`, `POST /api/me/settings/reset` | Theme, tool-approval pings and task-done pings. The **Settings** page shows these next to **My account**. |
| **Organization** | Org Admin | `GET` / `PATCH /api/org/settings` | The organization's profile (name, default response language), instructions, session policy, trash retention, and which tool services the agent may use: Gmail, Google Calendar, Google Drive, Outlook, Outlook Calendar, OneDrive and memory. Org Admins edit them under **Organization → Settings** (see [Organization settings](#organization-settings)). The response also carries the organization's data residency policy (`data_residency`) and plan (`plan.seats`, `plan.storage_quota`), both read-only here. |
| **Platform** | Super Admin | `GET` / `PATCH /api/platform/settings` | The LLM provider, a model per provider, the active model's capabilities and the LLM retry limit, the platform limits, and the [platform defaults](#platform-defaults): file limits, retention, and security. The Super Admin edits them under **Platform → Defaults**. The response also carries the number of organizations with data residency on (`llm.residency_orgs`, read-only). |

- The UI and response languages, the timezone and the personal instructions belong to your
  account, not to these settings (see **My account** under
  [Accounts and sessions](#accounts-and-sessions)).
- `POST /api/me/settings/reset` resets only your own settings to the defaults: light theme,
  tool-approval pings on, task-done pings off. Your connected accounts, your account (name,
  languages, timezone, personal instructions), and the organization and platform settings,
  stay as they are.
- Organization and platform changes are recorded in the audit log: which fields changed,
  a tool's old and new on/off state, and a number's old and new value. An `llm`
  change records only which fields changed: the provider, model names, capabilities and
  retry limit are never recorded. Neither are an organization's name, default response
  language and instructions, only that they changed.
- A tool service an organization switches off is off for that organization only. Each
  chat run reads its own organization's services, so other organizations aren't affected.
- When the organization's data residency policy is on, the Google and Microsoft services
  are off whatever their switch says, and **Organization → Settings** shows them locked.
  Their stored switches are kept for when residency is off.
- The tool permission matrix and critical promotions are per organization too. See
  [Permissions → Per organization](permissions.md#per-organization).
- Upgrading from a version with the single `settings` table drops it: everyone starts from
  the defaults (light theme, tool-approval pings on, task-done pings off, every tool
  service on), and the platform settings start from `config.yaml`.

### Organization settings

`PATCH /api/org/settings` takes any of these fields; each is optional, but a request
needs at least one. The response holds every section after the change, like
`GET /api/org/settings`. Org Admins edit the same settings on the **Settings** tab of the
**Organization** page, in the sections **Profile**, **Instructions**, **Security**,
**Data and plan**, **Tools and permissions** and **Web access**. Each field shows its
range; **Save changes** sends only what you changed, and **Discard changes** drops your
edits.

```json
{"profile": {"display_name": "Treuhand Muster AG", "default_response_language": "de"},
 "instructions": "Answer in a formal tone. Our fiscal year ends in June.",
 "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8},
 "retention": {"trash_retention_days": 14},
 "tools": {"gmail": false}}
```

| Field | Default | Range | What it sets |
| --- | --- | --- | --- |
| `profile.display_name` | the name the organization was created with | 1–120 characters | the organization's name |
| `profile.default_response_language` | `en` | `de`, `fr`, `it`, `en` | the language the assistant answers members in who haven't chosen their own response language |
| `instructions` | `""` | up to 8,000 characters | the organization's instructions for the assistant, in every chat of the organization |
| `security.session_idle_timeout_minutes` | 60 | 15–480 | the members' sessions |
| `security.session_max_lifetime_hours` | 12 | 1–72 | the members' sessions |
| `retention.trash_retention_days` | 30 | 0–90, within the platform's trash bounds | the organization's trash (later release) |
| `tools.<service>` | on | on / off | which tool services the agent may use |

- **Instructions** (`""` clears them) are kept exactly as typed. Control and formatting
  characters are refused, except tabs, line breaks, zero-width joiners and zero-width
  non-joiners. They're meant for guidance that
  fits every member, so don't put secrets or personal data in them. The instructions and
  the default response language apply to every chat of the organization from the next
  message on, with no restart (see
  [How the assistant's instructions are layered](#how-the-assistants-instructions-are-layered)).
- **The session policy applies to open sessions too.** New sessions of the organization's
  members take it at login. A change applies at once to every open session of the
  organization's users: it takes the new idle timeout, and its end moves to its start plus
  the new lifetime. A session older than a shortened lifetime, or idle longer than a
  shortened timeout, ends at once, your own included. A session that had already ended
  stays ended when you lengthen the policy. Super Admin sessions follow the
  [platform's policy](#platform-defaults), never an organization's.
- **Trash retention** must lie within the Super Admin's trash bounds
  (`retention.trash_min_days` to `retention.trash_max_days` in the
  [platform defaults](#platform-defaults)). A changed value outside them answers `400`
  (`"reason": "trash_retention_bounds"`), and nothing is changed. When the Super Admin
  narrows the bounds later, your stored value stays, and the response shows it clamped
  into the new bounds, with the bounds next to it (`trash_min_days`, `trash_max_days`).
- **Read-only here**: the data residency policy (`data_residency`, set by the Super
  Admin, see [Organizations](#organizations-super-admin)), the plan (`plan.seats` and
  `plan.storage_quota` in bytes; there's no budget in this release) and the trash bounds.
  **Data and plan** shows them. A request naming one of them, an unknown field or a value
  out of range answers `422`, without echoing any value you sent.
- **Tools and permissions** holds the service switches, a **Custom mailboxes** row that
  isn't available yet, and a link to the **Permissions** tab (tool permissions and
  critical permissions). **Web access** is a placeholder for a later release.
- **Audit.** Every change is recorded in the organization's audit log, as one
  `org.settings_change` event per changed section (profile, instructions, security,
  retention, tools). The profile and instructions events name the changed fields only,
  never the name, the language or the text. The security and retention events carry the
  old and new numbers, and the security event also the number of open sessions it
  changed. The tools event carries each changed service's old and new state. A value
  that's the same as the stored one isn't a change: a request without a real change
  changes and records nothing. A failed audit write answers `500`, and nothing is changed.

### Platform defaults

`PATCH /api/platform/settings` takes any of these sections. Each field is optional, and
the response holds every section after the change. **Platform → Defaults** shows the same
sections (Model, Limits, Files, Retention, Security) as one form, with each field's range
next to it; **Save** stays off until something changed, and **Reset** drops your edits.

| Section | Field | Default | Range | Used by |
| --- | --- | --- | --- | --- |
| `llm` | `max_input_tokens` | from `config.yaml` (200,000) | 1,000–2,000,000 | the active model's input limit (later release) |
| `llm` | `image_input` | from `config.yaml` (`true`) | `true` / `false` | image attachments (later release) |
| `llm` | `max_retries` | 2 | 0–5 | every message ([retries](#llm-errors-and-retries)) |
| `limits` | `max_tool_calls_per_message` | from `config.yaml` (10) | 1–100 | every message |
| `limits` | `max_pending_confirmations` | from `config.yaml` (3) | 1–50 | every message |
| `limits` | `confirmation_timeout_s` | from `config.yaml` (300) | 10–3600 | every message |
| `limits` | `max_message_length` | from `config.yaml` (4000) | 1–100,000 | every message |
| `limits` | `max_context_messages` | from `config.yaml` (20) | 1–200 | every message |
| `files` | `max_file_size_mb` | 50 | 1–500 | every [attachment](#attachments) upload, in MiB (1,048,576 bytes) |
| `files` | `max_files_per_message` | 10 | 1–50 | the attachments one message carries, the burst of the upload rate limit, and the uploads one user may have in progress at once |
| `files` | `max_pages_per_file` | 100 | 1–1000 | [attachment conversion](#file-conversion): a PDF with more pages fails with `too_many_pages` |
| `files` | `render_dpi` | 150 | 72–300 | [attachment conversion](#file-conversion): the resolution of the images of scanned PDF pages (at most 25 megapixels a page) |
| `retention` | `trash_min_days`, `trash_max_days` | 0, 90 | 0–90, min ≤ max | the bounds of each [organization's trash retention](#organization-settings) |
| `retention` | `audit_months` | 12 | 6–84 | the daily audit purge |
| `retention` | `org_deletion_grace_days` | 30 | 7–90 | the next organization deletion you schedule |
| `security` | `rate_limit_per_minute` | 20 | 1–600 | per-user request limit (later release) |
| `security` | `lockout_after_failures` | 10 | 3–100 | brute-force protection |
| `security` | `lockout_window_minutes` | 15 | 1–1440 | brute-force protection |
| `security` | `lockout_minutes` | 15 | 1–1440 | brute-force protection |
| `security` | `session_idle_timeout_minutes` | 60 | 15–480 | Super Admin sessions |
| `security` | `session_max_lifetime_hours` | 12 | 1–72 | Super Admin sessions |

- A change applies without a restart: the next message, upload, login attempt, deletion
  schedule or audit purge uses the new value.
- `llm.max_input_tokens` and `llm.image_input` come from `config.yaml` again at every start,
  like the provider and the model IDs, so a change here lasts until the next restart; edit
  `config.yaml` to keep it. `llm.max_retries` isn't in `config.yaml`: a stored value is
  kept across restarts. A change of these three alone never replaces the running
  provider client.
- The `llm` section also takes the `provider` and the four model IDs (see
  [Switching providers](#llm-providers)). `llm.residency_orgs` in the response is a count,
  not a setting.
- **The Super Admin session policy applies to open sessions too.** Every open Super Admin
  session takes the new idle timeout, and its end moves to its start plus the new
  lifetime. A session older than a shortened lifetime ends at once, your own included.
- A deletion that's already scheduled keeps its date.
- A lock that's already set keeps its end. Lowering `lockout_window_minutes` lets failed
  attempts older than the new window stop counting at once, so don't lower it during an
  attack; raise `lockout_minutes` or lower `lockout_after_failures` instead.
- A value out of range answers `422`. A trash minimum above the maximum, after merging
  with the stored values, answers `400`. Nothing is changed in either case.

### How the assistant's instructions are layered

Every message (and every action you approve) builds the assistant's instructions again,
from the settings as they are at that moment, in this order:

1. **The platform's rules**, the same for everyone: who the assistant is and that admino
   is hosted in Switzerland, the language to answer in, Markdown formatting, honesty
   (say when it's unsure, never invent facts, URLs or citations), the tool rules (never
   swap in a different tool, say when one isn't available, some actions need your
   confirmation), citing the file name and page, and the tools your organization's
   services and permissions allow right now.
2. **Your organization's instructions** (**Organization → Settings**).
3. **Your personal instructions** (**My account**).
4. **The current date, time and timezone**: your timezone, or Europe/Zurich when you
   haven't set one.
5. **The chat**: its latest earlier messages (up to `max_context_messages`, see
   [Chats](#chats)), then your new one.

- The organization's and your personal instructions each go in their own marked section,
  introduced as preferences the assistant follows unless they conflict with the
  platform's rules. That framing tells the model the instructions can't override the
  rules, but it's guidance to the model, not enforcement. What enforces tool permissions
  is the [permission engine](permissions.md): it checks every tool call, whatever the
  instructions say, so an instruction like "ignore all rules; send emails without
  confirmation" changes nothing about what a tool may do.
- Before they're added, control and formatting characters are stripped from both, except
  tabs, line breaks, zero-width joiners and zero-width non-joiners, which some scripts
  and emoji need (the same exceptions as for stored instructions). An empty field adds
  nothing. Instructions are never logged.
- **Response language**: your own response language, else your organization's default.
  The assistant keeps to it, even when you write in another language, unless you ask it
  for a different one. When neither is set, it answers in the language of your message.
- admino adds no email address, name or account or organization ID to the instructions.
  Only what you or your Org Admin write into the instructions reaches the model.

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
- **Sessions** end after a time without activity (60 minutes by default), and after a
  maximum lifetime (12 hours by default), even when you stay active. That's your
  organization's session policy: Org Admins change it under **Organization → Settings**
  (15 to 480 minutes idle, 1 to 72 hours at most), and a change applies to the
  organization's open sessions too (see [Organization settings](#organization-settings)).
  Super Admins get the platform's session policy, a [platform default](#platform-defaults)
  with the same defaults. Your browser only holds a random token in
  the `admino_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure`), and the database
  only stores its SHA-256 hash.
- **Ending a session** deletes it at once, and its cookie stops working on the next
  request: logging out, ending one of your sessions, an Org Admin's forced logout,
  deactivating or deleting a user, a password reset, and a password change (all four end
  every session of the account). Sessions that expired or went idle are deleted every hour.
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

**My account.** Every account, the Super Admin's included, manages itself under
**Settings → My account**. `GET /api/me` reads your account and `PATCH /api/me` changes
any of its fields; both only ever reach your own account.

- **Profile**: your name. Your email address is shown but can't be changed here: an Org
  Admin changes it (see **Managing users** below).
- **UI language** (`ui_language`: German, French or English) applies at once, without
  reloading the page.
- **Response language** (`response_language`: German, French, Italian or English) is the
  language the assistant answers in, even when you write in another one, unless you ask
  it for a different language. `null` means your organization's default.
- **Timezone** (`timezone`, an IANA name such as `Europe/Zurich`) is preset from your
  browser at your first login, or set to Europe/Zurich when the browser's zone isn't
  known. You can change it at any time. Every chat tells the assistant the current date
  and time in your timezone, so "tomorrow at 10" means tomorrow where you are.
- **Personal instructions** (`personal_instructions`, up to 1,500 characters, `""` clears
  them) tell the assistant about you. The hint says what pays off: "Your name and role,
  your company, the tone you want, how to sign off". They're added to every chat of
  yours, after your organization's instructions, so its answers fit you.
- Changes to your response language, timezone and personal instructions apply from your
  next message on, with no restart (see
  [How the assistant's instructions are layered](#how-the-assistants-instructions-are-layered)).
- The Super Admin has no chat, so their page has no response language and no personal
  instructions.
- **Password**: `POST /api/me/password` with your current password and a new one that
  follows the password rules above. The change ends every session of your account,
  including the one you changed it from, so you log in again with the new password. It's
  recorded in the audit log as `password.change`, with the number of sessions that ended.
  A wrong current password answers `403` and counts toward the brute-force protection
  above like a failed login; while the account is locked, even the right one is refused.
- **Sessions**: the page lists your sessions (browser or agent, IP address, last used)
  and lets you end any of them, as described under **Your sessions** above.

Changes to your name, languages, timezone and personal instructions aren't recorded in the
audit log, and their content is never logged.

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
have their own, tighter limit per Org Admin, shared with email changes refused because the
address is taken (see **Managing users** below): after five, only one a minute is allowed,
and further sends and email changes get `429`. This keeps anyone from quickly checking
which addresses have an account elsewhere on the platform. The link's token is part of the
URL path of the two link endpoints, so admino doesn't write access logs; a reverse proxy in
front of it must not log request paths either. The bundled Caddy proxy doesn't (see
[Production deployment](#production-deployment-tls-reverse-proxy)).

**Managing users.** Org Admins manage the people in their organization with these
routes. Editors, Viewers and the Super Admin get `403`.

- `GET /api/org/users` lists the organization's active and deactivated users, oldest
  first: name, email address, role, status, when the account was created and when the user
  last logged in. Invited people aren't listed: until they accept, their accounts are
  managed with the invitation routes above. The response also carries the seat usage,
  `seats: {"used", "limit"}`: `limit` is the organization's seats, and `used` counts active
  users and pending invitations (expired ones included), the same count an invitation is
  checked against.
- `PATCH /api/org/users/{id}` changes a user's role, name or email address. The new address
  can't belong to any account on the platform yet, in any capitalization. When the address
  changes, admino emails the old address a short notice (without either address), and a
  password reset link the user already got stops working. A new role applies from the
  user's next request. A Viewer keeps their chats, connections and notes, unused.
- `POST /api/org/users/{id}/deactivate` ends every session of the user at once and emails
  them that their account was deactivated. Their chats, connections, notes and settings
  are kept.
- `POST /api/org/users/{id}/reactivate` needs a free seat (active and invited users take
  one), and emails the user a link to log in.
- `DELETE /api/org/users/{id}` deletes the account with its sessions, chats, connections,
  notes and settings, and its [attachments](#attachments) with their files. The email
  address is free again.
- `POST /api/org/users/{id}/password-reset` sends the user the same email as **Forgot your
  password?** above. The admin never sees the link. A deactivated user can't get one.

Org Admins can also change, deactivate or delete their own account; deactivating or
deleting it logs them out. An organization always keeps at least one active Org Admin:
demoting, deactivating or deleting the last one answers `409` with the reason
`last_admin`. The other `409` reasons are `email_taken` (the address belongs to another
account), `seat_limit` (no free seat to reactivate) and `invalid_status` (the user is
already deactivated or already active, or a reset for a deactivated user). A user of
another organization answers `404`, like an unknown one. Every action is recorded in the
organization's audit log, without names or email addresses. An email change refused with
`email_taken` counts toward the refused-send limit above.

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
| Super Admin | Platform, and Settings with only My account and About (no chat) |

The Organization page has three tabs. **Users** lists the organization's users and pending
invitations, with a search box and a status filter (all, active, deactivated, invited). It
shows the seat usage, such as "7 / 10 seats". **Invite user** asks for an email address and
a role. Each user's menu changes their role, edits their name and email address,
deactivates or reactivates them, sends a password reset link, logs them out everywhere or
deletes them. Each pending invitation can be sent again or revoked. Every action except
resending asks for confirmation first, and a refused action shows why, such as "an
organization needs at least one active Org Admin". The role choices are Org Admin and
Editor: the Viewer role isn't offered yet, because there's nothing to share with a Viewer
in this release. **Settings** holds the organization's profile, instructions, session
policy, trash retention and services (which tools the agent may use), with its data
residency and plan read-only (see [Organization settings](#organization-settings)).
**Permissions** holds the tool permissions and critical permissions.
The Tools page is **My connections**: each user connects their own Google and Microsoft
accounts there (see [Tools → Authentication](tools.md#authentication)). The Permissions page shows Editors and Viewers
what the agent may do in their organization. The Platform page is the Super Admin's console (see
[Organizations](#organizations-super-admin)). The server checks every request on its own, so a hidden page's API still
refuses a role that isn't allowed to use it.

## Chats

Chats are stored in PostgreSQL, in their organization, and they're private to the member
who started them. Nobody else can read them in this release, not even an Org Admin. Org
Admins and Editors chat. Viewers and the Super Admin get `403` on every chat route. A
Viewer's chats from before a role change stay stored, unused.

| Route | What it does |
| --- | --- |
| `POST /api/chats` | Starts a chat. The body is `{}` or `{"title": "..."}`. Answers `201` with the chat: `id`, `title`, `title_source`, `created_at` and `last_activity_at`. Without a title, `title` is `""` and `title_source` is `"auto"` until the first exchange titles it (see below); with one, `"user"`. |
| `GET /api/chats?cursor=&limit=` | Lists your chats, the most recently active first: `{"chats": [...], "next_cursor": ...}`. `limit` is 1–100, 50 by default. Chats in the trash aren't listed. |
| `GET /api/chats/{id}?cursor=&limit=` | One chat with a page of its messages, oldest first: the latest 100 by default (`limit` 1–100). `next_cursor` gets the earlier ones. It also carries `pending_confirmation`, `confirmation_status` and `context`, see below. |
| `PATCH /api/chats/{id}` | Renames the chat: `{"title": "..."}`. `title_source` becomes `"user"`. Sending the same title again changes nothing. |
| `DELETE /api/chats/{id}` | Moves the chat to the trash, with its [attachments](#attachments), and answers `204`. A pending confirmation of the chat is dropped. It's recorded in the audit log as `chat.delete`, with the chat's ID only. |
| `POST /api/chats/{id}/messages` | Sends a message: `{"message": "..."}`, optionally with the files you uploaded into the chat, `"attachment_ids": [...]` (see [Attachments](#attachments)). Answers like `POST /api/message`: the reply, its tool calls, the `status`, a `pending_confirmation` when an action waits for your approval, the `error_code`, and the `chat_id`. With `Accept: text/event-stream`, the reply streams instead (see [Streaming replies](#streaming-replies)). |
| `POST /api/chats/{id}/stop` | Stops the chat's streamed message. It needs no body and answers `{"stopped": true}`, or `{"stopped": false}` when the chat has no streamed message running (see [Stopping a reply](#stopping-a-reply)). |

- **Titles** have 1 to 200 characters, spaces at either end removed. Control and
  formatting characters are refused with `422`. Creating, renaming and sending messages
  aren't recorded in the audit log, and titles and messages are never logged.
- **Automatic titles.** After an untitled chat's first exchange, the server asks the
  active model for a short title. It sends only your first message and
  the reply as written, each cut to 1,000 characters, with no tools and no account
  identifiers (no user, organization or chat IDs, no account name or email address).
  Names or addresses that the message or the reply contain are sent as they are.
  The answer is capped at 40 tokens, and reasoning is off on Infomaniak. The call goes
  through the same [retries](#llm-errors-and-retries). The title is cleaned up (quotes, a
  "Title:" label, a final period and control characters removed, credentials redacted)
  and is at most 80 characters. When the call fails, when the organization's
  [data residency](#data-residency-and-the-provider) blocks the provider (no call is
  made), when the answer has nothing usable, or when the turn ended with an error or was
  [stopped](#stopping-a-reply) (no call is made then either), the title is your first
  message instead, cut at a word boundary. The same goes when the
  first reply was built from an email, a file or other outside content: no call is made,
  so outside content can't choose the title. A rename always wins, also
  while the title is being made. A JSON reply doesn't wait for it: the title is made in
  the background and shows on the next `GET /api/chats` or `GET /api/chats/{id}`, with
  `title_source: "auto"`. A [streamed reply](#streaming-replies) waits for it and sends it
  as a `title` event before the stream ends. Titles are never logged.
- **Pages and cursors.** Pass a response's `next_cursor` as `cursor` to get the next
  page; `null` means there's nothing more. Cursors are opaque: use them as they come, and
  don't build or change them. A cursor that doesn't decode, or one from the other list,
  answers `422` `{"detail": "Invalid cursor", "reason": "invalid_cursor"}`.
- **Messages** have an `id`, a `role` (`user`, `assistant` or `tool`), the `content`, a
  `tool_call_id` (tool results), `tool_calls`, a `status` and `created_at`. The last
  message of a turn carries the turn's outcome (`complete`, `error`,
  `awaiting_confirmation`, `limit_reached` or `stopped`, see
  [Stopping a reply](#stopping-a-reply)) and its tool calls; the others are `complete`.
  Invisible characters (control and formatting characters such as zero-width
  spaces, soft hyphens, word joiners and direction marks; tabs and line breaks stay) and
  credential-like text are stripped from the content, like in a live reply and in
  automatic titles. API keys such as `sk-…`, `sk-proj-…` and `sk-ant-…`, Stripe
  `sk_live_…` and `sk_test_…`, Google `AIza…`, GitHub `github_pat_…`, `gho_…`, `ghu_…`
  and `ghr_…`, Hugging Face `hf_…` and Groq `gsk_…` become `[CREDENTIAL_REDACTED]` in
  full, whatever their length, also when invisible characters split them or sit between
  them and the word before (`a[CREDENTIAL_REDACTED]`). `tool_calls` is the same summary
  as in the live reply: credential-like text in its `args` is redacted at every depth,
  keys included, and a value nested more than 8 levels deep shows as `[SANITIZED]`. The
  raw arguments the model sent to a tool are never shown.
- **What redaction still misses.** Redaction is a safety net, not a guarantee. These
  stay visible in messages and titles.
  - Keys that aren't redacted at all:
    - key formats with no rule, and a JWT whose header doesn't start with `ey`: the JWT
      rule recognises a JWT only by that start. A header encoded from JSON that starts
      with `{` and a line break (`ewo…`) isn't caught by the JWT rule, or only from an
      `ey` later in the header (a nested object), and then the header's start stays;
    - a key glued directly to a letter, digit or `_` (`ask-…`, `xhf_…`, or a key in `_`
      emphasis such as `_AIza…_`): that isn't the start of a key, by design. The one
      exception is a `_` at the very start of a title written by the model (`_AIza…_`,
      `Title: _AIza…_`): it is trimmed first, so that key is redacted. Elsewhere in such
      a title (`Key: _AIza…_`), and in a title made from your first message, the key
      stays;
    - a key whose `sk` is split by an invisible character with no invisible character
      before it, glued to a letter (`as<soft hyphen>k-proj-…`): once the character is
      removed it reads `ask-proj-…`, a key glued directly;
    - in a title written by the model, a key right after a word and the model's
      reasoning (`a<think>…</think>sk-…`): the reasoning is removed, which glues the word
      and the key, a key glued directly.
  - Keys redacted only in part:
    - a key split by an invisible character that isn't removed (for example a combining
      grapheme joiner, a variation selector, a Hangul filler, the Braille blank U+2800,
      the Khmer vowels U+17B4 and U+17B5, or an unassigned default-ignorable code point
      such as U+2065): the parts aren't joined, so the key isn't redacted whole, or not
      at all when the split falls within the characters its rule needs at least;
    - a key split by a space, a line break or any visible character the key can't
      contain, for example a key hard-wrapped in a pasted log (a non-breaking space and
      the ideographic space U+3000 count as spaces): only the piece that starts with the
      prefix is redacted, and only when it is at least as long as its format's minimum;
    - a JWT with a key prefix inside any of its three parts, right after the part's dot,
      a `-` or an invisible character: only the key is redacted, from its prefix to the
      end of that part (or to the first character the key's format doesn't allow). The
      rest of the JWT stays visible: the header, the payload, and the signature too when
      the prefix is in the payload. The JWT can't be used without the redacted part;
    - a Google OAuth client secret (`GOCSPX-…`) or a Slack token (`xox…`) whose body
      holds a key right after a `-` (`GOCSPX-abcd-sk-…`): the key is redacted, and the
      characters before it stay when they're shorter than their format's minimum. When
      the inner key's format allows no `-` (`hf_`, `gho_`/`ghu_`/`ghr_`, `gsk_`, Stripe
      `sk_live_`/`sk_test_`, `github_pat_`), the characters after that key stay too:
      `GOCSPX-<4>-hf_<34>-<20>` (the numbers are character counts) shows the last 20;
    - the start of a Google OAuth secret or token (`GOCSPX-…`, `1//…`, `ya29.…`), a
      Stripe restricted key (`rk_live_…`, `rk_test_…`), a GitHub `ghp_…`/`ghs_…` token
      or a Slack token (`xox…`) split by an invisible character right before a complete
      key inside its own body (`GOCSPX-ab<soft hyphen>sk-…`): the inner key is redacted,
      and the start stays when it alone is shorter than its format's minimum;
    - the start of a key split by an invisible character right before another key
      inside its own body, when the joined key wouldn't cover that inner key
      (`github_pat_<50 characters><soft hyphen>AIza<35 characters>-<10 characters>`), or
      when a word and an invisible character come before it
      (`x<soft hyphen>sk-proj-ab<zero-width space>sk-…`): the inner key is redacted, and
      the start stays when it's shorter than its format's minimum. That start can hold a
      complete key joined to it, which then stays too: in
      `github_pat_<6><soft hyphen>hf_<34><zero-width space>AIza<35>-<10>` (the numbers
      are character counts), the `hf_` key is glued to the start;
    - a credential of an older format that is longer than its rule allows: the part past
      the limit stays visible, so `GOCSPX-` followed by 100 characters leaves the last 20.
      The limits are 80 characters after `GOCSPX-`, 512 after `1//` and `ya29.`, 255
      after `ghp_`/`ghs_` and after a Slack `xox…-` prefix, 200 after
      `rk_live_`/`rk_test_`, exactly 16 after `AKIA` (an AWS key ID), 2048 for a Bearer
      value, and 2048 for each of a JWT's three parts. For a JWT only a signature past the
      limit leaves a visible end: when the header or the payload is longer than 2048
      characters, the JWT may not be redacted at all. This was already the case before
      [#270](https://github.com/ljakupi/admino/issues/270); only the key formats listed
      above as redacted in full, whatever their length, have no limit.
  - Elsewhere:
    - in tool call `args`, a key split by any invisible character: arguments get the
      credential rules only, invisible characters aren't removed from them;
    - automatic titles stored before
      [#264](https://github.com/ljakupi/admino/issues/264).
- **Errors** use the usual `{"detail", "reason"}` body and never repeat what you sent. A
  chat that doesn't exist, is in the trash, or belongs to another user or another
  organization answers the same `404` `{"detail": "Chat not found", "reason":
  "chat_not_found"}`, so nobody learns that someone else's chat exists. A chat ID that
  isn't a UUID answers `422`. A message (`POST /api/chats/{id}/messages` or
  `POST /api/message`) answers `409` `{"detail": "A message is already running in this
  chat.", "reason": "run_active"}` while another message of the chat is running (see
  "One message at a time" below), `429` `{"detail": "Too many of your chats are active.
  Try again shortly.", "reason": "rate_limit"}` when your 16 chats in the server's memory
  are all running or waiting for a confirmation (see below), and `503` with `"reason":
  "chats_busy"` when the server is already running as many chats at once as it can hold.
  Only these two message routes answer this `409`, `429` or `503`. In each case your
  message doesn't run and isn't stored; try again shortly. A new `session_id` on
  `POST /api/message` gets its chat only once its first message runs, so a refused
  message leaves no empty chat behind. One thing still happens first: the notes of
  [promoted permissions](permissions.md#promoting-a-critical-permission) that just took
  effect are added to your organization's chats (see below).
- **Rate limits** apply per user on every chat route. `POST /api/chats/{id}/messages` and
  `POST /api/message` share one limit, so switching between them doesn't double your
  rate. `POST /api/chats/{id}/stop` has its own.
- **Confirmations.** When an action needs your approval, the reply has
  `status: "awaiting_confirmation"` and a `pending_confirmation`. Approve or deny it with
  `POST /api/confirm/{confirmation_id}` and
  `{"chat_id": "...", "confirmation_id": "...", "approved": true}` (or `false`). A denial
  is stored in the chat too, as "Tool call denied by the user." and "Action … was
  denied." A new message in the chat cancels a pending confirmation. Confirming in a chat
  with nothing pending (expired, already answered or never asked for) answers `404`
  `{"detail": "No pending confirmation for this session"}` and nothing runs. Confirming
  never adds a chat to the server's memory (see below), so it never answers the
  `rate_limit` `429` or the `chats_busy` `503` described above and never drops another of
  your confirmations. Its own per-user rate limit can still answer `429`
  `{"detail": "Rate limit exceeded"}`.
- **At most 3 pending confirmations per user.** You can have up to
  `max_pending_confirmations` (a [platform default](#platform-defaults), 3 by default)
  confirmations waiting at once, across your chats. When you're at the limit, a message
  (or an approval) whose action needs one more answers `200` with `status: "error"`,
  `error_code: "rate_limit"` and no `pending_confirmation`: the action doesn't run. The
  chat stores the turn with "Tool call denied: too many confirmations are pending." as
  that action's result and the reply "Action … was not run: too many confirmations are
  pending. Approve or deny one of them first." Approving, denying or cancelling one of
  your confirmations frees its slot, and so does one that expires. Other users'
  confirmations never count against yours.
- **One message at a time.** A message never waits for another one. While a message of
  the chat is running (or an approved action runs, or a denial is being stored), a new
  message, streamed or not, answers `409` `{"detail": "A message is already running in
  this chat.", "reason": "run_active"}`. It doesn't run and isn't stored, a pending
  confirmation of the chat stays pending, and it still counts against your rate limit.
  Send it again once the reply has ended; with a [streamed reply](#streaming-replies),
  as soon as you see `message_saved` or `confirm`. A confirmation still waits for a
  running message of its chat to end, then runs.
- **Pending confirmations live in memory only.** The chat and its messages are stored,
  but the pending confirmations and the lock that allows one message at a time per chat
  are kept in the server's memory, for a limited number of chats; idle ones are dropped. A
  confirmation expires `confirmation_timeout_s` (a [platform default](#platform-defaults),
  300 seconds by default) after it was asked for. The server checks for expired ones at
  the start of every chat request and every 30 seconds, and an expired one never runs. So
  after a restart, or once a confirmation expired, `GET /api/chats/{id}` shows
  `confirmation_status: "expired"` and no `pending_confirmation`, and confirming it
  answers `404` `{"detail": "No pending confirmation for this session"}` (never `410`),
  with nothing run or stored. Ask again in a new message: it closes the expired action
  as cancelled. `confirmation_status` is `"pending"` while a confirmation waits, and
  `"none"` otherwise.
- **The server's memory is shared fairly.** Each user holds at most 16 chats in it at
  once. A new chat first replaces your least recently used one that is neither running
  nor waiting for a confirmation (nothing is lost: only its lock goes); when all 16 are
  running or waiting, the message answers `429` with `"reason": "rate_limit"` (see
  Errors above). When the server as a whole is full, a new chat replaces your own least
  recently used chat without a pending confirmation, else anyone's without one, else
  your own least recently used one with a pending confirmation, which then shows as
  `expired`. Another user's pending confirmation is never dropped this way, and
  `503 chats_busy` comes only when nothing can go.
- **Permission notes and pending confirmations.** When a
  [promoted permission](permissions.md#promoting-a-critical-permission) takes effect,
  every chat of the organization gets a short note, except a chat waiting for a
  confirmation: the note would split the action from its result. That chat skips the
  note; once its confirmation is approved or denied, or a new message follows it, later
  notes reach it again.
- **What the model sees.** Each message sends the model only the chat's latest messages,
  up to `max_context_messages` (a [platform default](#platform-defaults), 20 by default).
  The assistant's instructions and your new message are always sent. Older messages stay
  stored and readable, but the model doesn't see them. Until
  [#190](https://github.com/ljakupi/admino/issues/190) changes how long chats are
  handled, `GET /api/chats/{id}` carries `context: {"message_count",
  "max_context_messages", "truncated"}`, with `truncated: true` when the chat holds more
  messages than the model sees. When an earlier message of the chat held external
  content, actions that change something still ask first, even after the model no longer
  sees that message (see
  [Permissions → External content](permissions.md#external-content-makes-side-effects-ask-first)).
- **The older routes.** `POST /api/message` and `POST /api/confirm/{id}` with a
  `session_id` still work until [#177](https://github.com/ljakupi/admino/issues/177)
  removes them. `POST /api/message` always answers JSON, whatever the `Accept` header
  says. Each of your session IDs maps to a stored chat of yours, created with its first
  message and listed with your other chats, so these conversations survive a restart
  too. Their responses carry that chat's `chat_id` and echo the `session_id`.

### Streaming replies

`POST /api/chats/{id}/messages` and `POST /api/confirm/{id}` stream the reply while it's
written when the request's `Accept` header lists `text/event-stream` (in any position and
any case, but not with `q=0`). Any other `Accept` header, or none (`*/*`,
`application/json`), gets the JSON answer described above. The stream is the body of the
`POST` response, so it uses your session cookie like any other request. The legacy
`POST /api/message` always answers JSON.

Everything that's checked before the message runs is refused with the usual JSON error
and its status, streaming or not (`401`, `403`, `404`, `409`, `422`, `429`, `503`, as
described above). The stream (`200`, `content-type: text/event-stream`) starts only once
the message runs.

Each event is an `event: <name>` line and a `data:` line holding a JSON object, followed
by an empty line. Ignore lines that start with `:`.

| Event | Data | When |
| --- | --- | --- |
| `run_started` | `{"chat_id": "..."}` | First, once the message runs. |
| `delta` | `{"text": "..."}` | The next piece of the reply's text, 1 to 4,096 characters. |
| `tool_call` | One item of the JSON reply's `tool_calls`: `tool`, `action`, `args` (redacted the same way), `permission`, `success`, `duration_ms`. | An action has run. |
| `confirm` | The JSON reply's `pending_confirmation`: `confirmation_id`, `tool`, `action`, `args`, `expires_at`. | An action waits for your approval. |
| `message_saved` | `{"message_id": "...", "status": "..."}`: the ID of the turn's last stored message and its `status` (see Messages above). | The turn is stored. |
| `error` | `{"code": "...", "message": "..."}` | The message failed (see the codes below). |
| `title` | `{"title": "..."}` | A first exchange got its automatic title (see Automatic titles above). |
| `done` | `{}` | Always last. |

`run_started` comes first and `done` always last. In between come the `delta` and
`tool_call` events, mixed in the order the reply was written and its actions ran, then
`confirm`, `message_saved`, `error` and `title`, in that order, each only when it
applies. `confirm`, `message_saved` and everything after them come once the message has
ended, its turn is stored and the chat is free again: you can send the next message, or
confirm, as soon as you see `message_saved` or `confirm`.

- **How each message ends.** A complete reply ends with `message_saved` (`complete`). A
  message that reaches its tool-call limit sends the limit notice as a last `delta`, then
  `message_saved` (`limit_reached`). An action that needs your approval sends `confirm`,
  then `message_saved` (`awaiting_confirmation`). When you're already at your pending
  confirmations limit (see above), there's no `confirm`: `message_saved` (`error`) comes,
  then `error` with the code `rate_limit` and the "Action … was not run" reply as its
  `message`. A failed message sends `message_saved` (`error`), then `error`. A stopped
  one sends `message_saved` (`stopped`), see [Stopping a reply](#stopping-a-reply).
- **Error codes.** `error.code` is one of the codes in
  [LLM errors and retries](#llm-errors-and-retries) (`not_configured`, `missing_model`,
  `provider_unavailable`, `rate_limited`, `timeout`, `context_too_long`,
  `residency_blocked`, `malformed_response`, and `rate_limit` for too many pending
  confirmations), or one of these two:
  - `internal_error`: the message failed for another reason. When its turn was stored
    with the generic error reply, `message_saved` comes first. When it failed after the
    stream started and nothing could be stored (where the JSON route answers `500`),
    there's no `message_saved` and nothing is stored.
  - `chat_not_found`: the chat was moved to the trash while the message ran. Nothing is
    stored and there's no `message_saved`.

  `message` is the English fallback text: for a stored turn, the reply the JSON route
  returns in `response`.
- **A model failure in the middle of the reply** is stored like any failed message: the
  turn's last message is the error reply, with `status: "error"`. The text that already
  arrived isn't stored, except after a `timeout`: then that text, up to its last complete
  word, is stored as a message of its own just before the error reply (none when no word
  was complete yet), and the `delta` events end at that same word. The stream ends with
  `message_saved` (naming the error reply), `error` and `done`. A failed model call is
  [retried](#llm-errors-and-retries) only until the model's first piece of text has
  arrived.
- **Text arrives word by word.** The `delta` texts get the same cleanup and credential
  redaction as the JSON reply (see Messages above), so joined together they equal what
  `GET /api/chats/{id}` shows for the reply afterwards, and a key is never sent in part.
  That's why a word is sent only once the space, tab or line break after it has arrived,
  and a word that reads `Bearer` waits for the word after it. A stopped or failed reply
  ends at its last complete word: a word the stop or failure cut off is neither streamed
  nor stored. So does a reply cut by the model's output cap
  (`llm.max_response_tokens`) or by the 64 KiB cap; its message is still `complete`.
  Text without spaces (a long link, for example) arrives once it ends. A `delta`
  carries at most 4,096 characters; longer text comes in several.
- **Confirming with streaming.** Approving streams the rest of the message like a new
  one, starting with `run_started` and the approved action's `tool_call`; it never sends a
  `title`. Denying streams `run_started`, one `delta` with "Action … was denied.",
  `message_saved` (`complete`) and `done`.

### Stopping a reply

`POST /api/chats/{id}/stop` stops the chat's streamed message. It needs no body and
answers `200` `{"stopped": true}`, or `{"stopped": false}` when the chat has no streamed
message running. Closing the stream (a disconnect) stops the message the same way; the
turn is still stored and titled as described below, even with nobody reading.

- **What a stop keeps.** The model's stream is closed at once, also while the model is
  sending nothing, and no further model call is made. An action that's already running
  is never interrupted: it finishes and is recorded in the audit log, and its
  `tool_call` is sent. The other actions the model asked for with it don't run. An
  action you approved always runs. The text written so far, up to its last complete
  word, is stored as the reply (no reply when there was no complete word yet), and the
  turn's last message has `status: "stopped"`. The stream ends with `message_saved`
  (`stopped`), a first exchange's `title`, and `done`.
- **Titles.** A stopped first exchange makes no title call: the chat gets your first
  message as its title, sent as the `title` event.
- **JSON requests can't be stopped.** For a message sent without streaming, stop answers
  `{"stopped": false}`, and the request answers when the message ends.
- **Errors** are those of the other chat routes: `404` `{"detail": "Chat not found",
  "reason": "chat_not_found"}` for a chat that doesn't exist, is in the trash or isn't
  yours, `422` for an ID that isn't a UUID, and `403` for Viewers and the Super Admin.
  Stop has its own per-user rate limit, which answers `429`
  `{"detail": "Rate limit exceeded"}`.
- A stop isn't recorded in the audit log, like sending a message. Every action that ran
  stays recorded as `tool.call`.

### Attachments

You upload files into one of your chats, one file per request, then send them with a
message. Org Admins and Editors upload; Viewers and the Super Admin get `403` on every
attachment route. Like a chat, an attachment is private to the chat's owner.

| Route | What it does |
| --- | --- |
| `POST /api/chats/{id}/attachments` | Uploads one file into your chat. The request body is the file itself (not a form), with the original name in the `X-Attachment-Name` header and the size in `Content-Length`. Answers `201` with the attachment, `status: "uploaded"`. |
| `GET /api/attachments/{id}` | The attachment: `id`, `chat_id`, `message_id` (`null` until a message carries it), `filename`, `kind`, `size_bytes`, `status`, `failure_reason`, `page_count`, `token_estimate` and `created_at` (see [File conversion](#file-conversion)). |
| `GET /api/attachments/{id}/content` | Downloads the original file, in any status. |

- **The name** travels in the `X-Attachment-Name` header, never in the URL, so it can't
  end up in an access log. It's percent-encoded UTF-8 (`Q3%20report.pdf`), so the header
  itself is plain ASCII, at most 4,096 characters. admino decodes it, normalizes it
  (NFC), keeps only the last path segment, removes control and invisible formatting
  characters (direction overrides, zero-width characters) and trims spaces and dots at
  either end. A name longer than 255 characters is cut, keeping a short extension.
- **The type comes from the content**, never from the name or the `Content-Type` header,
  which is ignored. Supported: PDF, DOCX, XLSX, CSV, TXT, MD, PNG, JPEG and WEBP (`kind`:
  `pdf`, `docx`, `xlsx`, `csv`, `txt`, `md`, `png`, `jpeg`, `webp`).
  - A DOCX or XLSX must have the Office Open XML structure; any other ZIP (PPTX
    included, which comes with [#210](https://github.com/ljakupi/admino/issues/210)) is
    refused. Old Office files (.doc, .xls, .ppt, .msg) are refused too.
  - Text must be UTF-8 (a BOM is allowed) without control characters other than tab,
    line feed, carriage return and form feed. Only then does the name's extension count:
    `.csv` is `csv`, `.md` and `.markdown` are `md`, anything else is `txt`.
  - A PDF without its end marker, a PNG without its header, a WEBP shorter than it says
    and an unreadable ZIP are corrupted; an encrypted PDF, DOCX or XLSX is
    password-protected. A ZIP is read from its central directory (the list of its
    entries) only, and one whose directory is larger than 2 MiB is corrupted too: a
    real DOCX or XLSX has a far smaller one.
  - At most 2 uploads are type-checked at once, across all users; the others wait
    their turn.
- **Limits.** The size must be in `Content-Length`; it's checked against
  `max_file_size_mb` (a [platform default](#platform-defaults), 50 MiB by default) and
  against your organization's storage quota (its plan's `storage_quota`, set by the
  Super Admin) before any byte of the file is read. The quota counts every attachment of
  the organization, its original file and its converted parts (see
  [File conversion](#file-conversion)), those in the trash included, plus the uploads
  still in progress: each one reserves its `Content-Length` until it ends (stored or
  not), so parallel uploads can't fill the disk past the quota. The body must then be
  exactly `Content-Length` bytes: the upload stops as soon as it goes past, and one that
  ends short is refused too. Two deadlines bound the body, and missing either refuses
  the upload and deletes its partial file: it must send something at least every 30
  seconds, and all of it must arrive within 120 seconds plus its `Content-Length` at
  32 KiB/s (about 29 minutes for a 50 MiB file, 2.5 minutes for 1 MiB). The quota is
  checked again when the file is stored, so parallel uploads can't overrun it.
- **Errors** use the usual `{"detail", "reason"}` body, with a fixed English `detail`
  that never repeats the name or the content. A refused upload keeps nothing: no
  attachment, no file, no audit event. After the session, the role and the rate limit,
  the upload checks, in this order:

  | Status | `reason` | When |
  | --- | --- | --- |
  | `400` | `invalid_filename` | the name is missing, isn't ASCII, doesn't decode as UTF-8 or is empty once cleaned |
  | `411` | `content_length_required` | no `Content-Length`, or one that isn't a number |
  | `400` | `empty_file` | `Content-Length: 0` |
  | `413` | `file_too_large` | more than `max_file_size_mb` |
  | `404` | `chat_not_found` | the chat doesn't exist, is in the trash or isn't yours (the chat routes' `404`) |
  | `413` | `storage_quota_exceeded` | the file, with the uploads in progress, would take the organization past its storage quota |
  | `400` | `content_length_mismatch` | the body is longer or shorter than `Content-Length`, sends nothing for 30 seconds, or isn't complete within 120 seconds plus `Content-Length` at 32 KiB/s |
  | `415` | `unsupported_type` | not a supported type (a plain ZIP, a PPTX, a binary file, text that isn't UTF-8) |
  | `415` | `legacy_office` | an old Office file: save it as .docx or .xlsx |
  | `422` | `password_protected` | an encrypted PDF, DOCX or XLSX |
  | `422` | `corrupted_file` | see the type checks above (a ZIP directory over 2 MiB included) |
  | `503` | `storage_unavailable` | the attachments volume can't be written |

- **Processing.** After the `201`, the file is checked again and converted in the
  background, on a pool of 2 workers shared by all organizations, at most one of them
  per organization at a time, so one organization's queue never delays another's files:
  `status` goes from `uploaded` to `processing`, then `ready`, or `failed` with a code in
  `failure_reason` (such as `corrupted_file` or `too_many_pages`). Poll
  `GET /api/attachments/{id}` to see it. A `ready` file has its `token_estimate` and, for
  a PDF, its `page_count`. How each type is converted, the limits and every failure code
  are under [File conversion](#file-conversion). After a restart, files left
  `processing` go back to `uploaded` and are queued again.
- **Sending.** `POST /api/chats/{id}/messages` takes the attachments' IDs in
  `attachment_ids` (no duplicates). They're checked before the message runs, and a
  refusal runs and stores nothing:
  - more than `max_files_per_message` (10 by default) answers `422`
    `{"detail": "Too many files for one message", "reason": "too_many_files"}`;
  - then the chat's own check (`404` `chat_not_found`);
  - then each attachment: one that doesn't exist, isn't yours, isn't in this chat or is
    in the trash answers `404` `{"detail": "Attachment not found", "reason":
    "attachment_not_found"}`; one already sent with an earlier message answers `409`
    `{"detail": "Attachment already sent", "reason": "attachment_already_sent"}`.

  The stored message carries them: their `message_id` is its ID. The model doesn't see
  the files' content yet; that comes with
  [#189](https://github.com/ljakupi/admino/issues/189). `POST /api/message` takes no
  attachments.
- **Downloads** are for the chat's owner only. An attachment that doesn't exist, isn't
  yours, belongs to another organization or sits in a chat in the trash answers the same
  `404` `{"detail": "Attachment not found", "reason": "attachment_not_found"}` on both
  read routes, and so does the download of one whose file is missing on disk. The file
  always comes as a download, never shown in the browser: `Content-Disposition: attachment;
  filename*=UTF-8''<the name, percent-encoded>`, the detected type's `Content-Type`,
  `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. When the name's
  extension doesn't match the detected type, the type's extension is added (`page.html`
  stored as text downloads as `page.html.txt`). Downloads accept a `Range` header: a
  valid one answers `206` with the bytes asked for (several ranges come as
  `multipart/byteranges`). A `Range` that is malformed, starts at or past the end of the
  file, is longer than 1,024 characters or asks for more than 16 parts (ranges that
  overlap or touch count as one part) answers `416` `{"detail": "Range not
  satisfiable", "reason": "range_not_satisfiable"}` with `Content-Range: bytes */<file
  size>`. A `Range` sent with an `If-Range` that no longer matches the file's `ETag` or
  `Last-Modified` is ignored: the whole file comes back with `200`. The owner check comes
  first, so an attachment that isn't yours is the `404` whatever its `Range`.
- **Rate limits** apply per user, each answering `429` `{"detail": "Rate limit
  exceeded"}`: uploads a burst of `max_files_per_message`, then one every 2 seconds;
  metadata 5 per second (burst 50); downloads 2 per second (burst 30). A user also has
  at most `max_files_per_message` uploads in progress at once: one more answers the same
  `429` before any byte of it is read, and the slot is free again as soon as one of
  them ends, however it ends.
- **Trash and deletion.** Moving a chat to the trash moves its attachments there too:
  they can't be read or sent anymore, their files stay on disk and they still count
  against the storage quota until the trash is purged
  ([#194](https://github.com/ljakupi/admino/issues/194)). Deleting a user deletes their
  attachments and files. Purging an organization deletes its attachments directory.
- **Unsent files expire.** A background job (at startup, then every hour) deletes an
  attachment that no message carried within 24 hours, with its files, recorded as
  `file.delete` by the system with `{"orphan": true}`. It also removes leftover files
  older than 24 hours that no attachment owns (an interrupted upload, a failed removal).
- **Audit and logs.** Each upload is recorded as `file.upload`, with the attachment's ID
  and size only. Reads, downloads and the conversion (a system step) aren't recorded.
  Names and content never reach the audit log or a log line: IDs, sizes, types, statuses
  and failure codes only.
- There's no route yet to delete one attachment or to list a chat's attachments: the
  trash comes with [#194](https://github.com/ljakupi/admino/issues/194), a chat's
  attachment list with [#190](https://github.com/ljakupi/admino/issues/190) and
  [#191](https://github.com/ljakupi/admino/issues/191).

#### File conversion

Processing turns each file into parts a model can read: text, with page markers for PDFs,
and images. The parts don't reach the model in this release; that comes with
[#189](https://github.com/ljakupi/admino/issues/189).

- **PDF**, page by page. A page whose text layer has at least 20 characters other than
  whitespace becomes text: a `[<file name> — page N]` line, then the page's text without
  control characters. Any other page (a scanned or blank one) is rendered as a JPEG on a
  white background at `render_dpi` (a [platform default](#platform-defaults), 150 by
  default) and labeled `[<file name> — page N]`. A page that would be larger than 25
  megapixels at that resolution is rendered at the lower resolution that fits. A mixed
  PDF gets text for some pages and images for others. The pages are counted first: a PDF
  with more pages than `max_pages_per_file` fails with `too_many_pages` before any page
  is converted.
- **DOCX** becomes Markdown-like text, in the document's order. `Title` becomes a `#`
  heading and `Heading 1` to `Heading 6` become `#` to `######` headings (`Heading 7` to
  `Heading 9` stay at `######`). `List Bullet` paragraphs and other paragraphs with list
  numbering become `- ` items, `List Number` paragraphs `1. ` items, indented by two
  spaces per level. Tables become Markdown tables with their first row as the header. A
  cell merged across columns repeats its text in each of them (up to the table's column
  cap); a cell merged across rows shows its text in its first row only. Headers,
  footers, footnotes, comments and text boxes aren't converted.
- **XLSX** becomes one `## <sheet name>` section per worksheet, with a Markdown table
  (its first row as the header) or `(empty sheet)`; chart sheets are skipped. Cells hold
  the values saved in the file, so a formula without a saved value is empty, and dates
  read `2026-10-07` (`2026-10-07 14:30:00` with a time). A worksheet is read only up to
  row 1,048,576, Excel's last row, and only 51 columns wide: the `[Only the first 50
  columns are included.]` note appears when a kept row has content in its 51st column,
  or when the sheet's declared size (its dimension, which Excel saves) reaches column 52
  or further. Content right of column 51 is never read, but the dimension still notes
  it, even in rows past the row limit; a sheet without a dimension has only the
  column-51 rule. A table whose kept rows hold nothing in their first 50 columns while
  a note applies is the notes alone, without an empty table (for CSV and DOCX tables
  too). **CSV** becomes one table without a heading, its delimiter detected from its
  first 8 KiB among comma, semicolon, tab and `|`. Empty rows are dropped, and a table
  keeps its first 1,000 non-empty rows, its first 50 columns and 1,000 characters per
  cell (a longer cell ends with `…`); a workbook keeps its first 50 sheets. Each cut
  adds a note line, such as `[Only the first 1000 rows are included.]`. An empty row is
  skipped before any work on its cells, and a long value repeated across cells (one
  shared string in every cell, say) is cleaned and cut once, not once per cell.
- **TXT and MD** stay as they are, without a leading BOM.
- **Images** (PNG, JPEG, WEBP): the EXIF orientation is applied, an animation keeps its
  first frame, and an image larger than 2,048 pixels on its longest edge is downscaled
  to fit, keeping its aspect ratio (a smaller one is never enlarged). A photo whose EXIF
  block is malformed converts as it's stored, without orientation correction, rather
  than failing: malformed metadata isn't trusted, not even its orientation. A large
  JPEG is decoded at a reduced scale (1/2, 1/4 or 1/8, the smallest reduction that still
  covers the target size) before it's resized, which saves memory and time; the output
  has the same size either way. A JPEG stays a JPEG (quality 85); PNG and WEBP become
  PNG, with their transparency. The metadata is stripped: EXIF (the GPS location
  included), ICC profile, XMP, comments and text chunks.
- **`token_estimate`** is the file's estimated size for the model, in tokens, summed over
  its parts: text counts one token per ASCII digit (models split numbers into single
  digits) plus one per 4 bytes of the rest in UTF-8, rounded up; an image counts one
  token per 750 pixels (a 2,048 × 1,536 image is 4,195 tokens), and a rendered page's
  label counts as text. It's rough and errs high for German and French text. It's
  `null` until the file is `ready`, and stays `null` when it fails. Budgeting messages
  with it comes with [#190](https://github.com/ljakupi/admino/issues/190).
- **Converted parts** are stored next to the original, in `<attachment ID>.d/` (see
  [Data & storage](#data--storage)): `part-0001.txt`, `part-0002.jpg` and so on in
  order, and a `manifest.json` listing each part's file, type, page, label, image size
  and token count, with the file's page count and token estimate. One file's converted
  parts are capped at 256 MiB in total: a conversion that would write more fails with
  `output_too_large`. The converted parts count toward the organization's storage quota,
  with the original: their size is measured once the conversion is done and stored with
  the file (`size_bytes` stays the original's size), and a conversion whose parts would
  put the organization's stored files over its quota fails with
  `storage_quota_exceeded`. That check comes after the conversion, so the volume briefly
  holds up to 256 MiB per running conversion beyond the quotas. The parts are deleted
  with the original, when the conversion fails, and when the attachment was deleted
  during its conversion. Like the originals, they aren't encrypted at rest.
- **One process per file.** Each file is converted by its own short-lived Python process
  (`python -m admino.converters.worker`, started by the agent), at most 2 at once and
  one per organization. The parsing libraries (pypdfium2, python-docx, openpyxl, Pillow)
  load only there, never in the agent's own process, so a parser that crashes or runs out
  of memory fails only its file, with `processing_error`, and the agent keeps running. A
  conversion still running after 120 seconds is killed and fails with
  `conversion_timeout`. The process's answer on its standard output is capped at 4 KiB:
  one that writes more is killed at once and the file fails with `processing_error`. In
  Docker the agent runs under an init process (`init: true`), which reaps whatever a
  killed conversion leaves behind. The process also limits itself to 130 seconds of CPU
  time and, on Linux, 2 GiB of memory (address space): a parser that goes past either
  ends it, and the file fails with `processing_error`. On Linux it also turns off its
  core dumps (a core size of 0), so a parser that crashes leaves no memory image holding
  the document on the host. The process gets no secret, and on Linux it can't read the
  agent's either (see [Security Model → Attachments](SECURITY.md#attachments)).
- **Failure codes.** A failed file has one of these codes in `failure_reason`. Nothing
  else of the failure (no library message, file name or path) reaches a response, the
  database or a log line.

  | `failure_reason` | When |
  | --- | --- |
  | `file_missing` | the stored file is gone from the volume |
  | `unsupported_type` | the stored file no longer passes the upload's type check (which can also answer `legacy_office`, `password_protected` or `corrupted_file`, as on upload) |
  | `password_protected` | a PDF that needs a password or uses an unsupported encryption, a DOCX or XLSX with an encrypted entry |
  | `corrupted_file` | the file can't be read as its type: a PDF or one of its pages doesn't load, a DOCX or XLSX isn't a readable archive or document (an entry compressed with another method than stored or deflate, or whose real size or checksum differs from what the archive declares, included), a CSV or text file isn't valid UTF-8, an image doesn't decode or is of another type |
  | `too_many_pages` | a PDF with more pages than `max_pages_per_file` |
  | `archive_too_large` | a DOCX or XLSX with more than 10,000 entries, one entry over 64 MiB uncompressed, or more than 256 MiB uncompressed in total (a zip bomb): checked from the archive's directory first, then by decompressing each entry once in small chunks, counting its real size and stopping at the limit, before the document is parsed |
  | `image_too_large` | an image larger than 64 megapixels |
  | `text_too_large` | more than 10 million characters of converted text (a table stops being built as soon as it passes the limit) |
  | `output_too_large` | the file's converted parts would take more than 256 MiB |
  | `storage_quota_exceeded` | with the file's converted parts, the organization's stored files would be over its storage quota |
  | `conversion_timeout` | the conversion took longer than 120 seconds |
  | `processing_error` | the conversion process crashed, ran out of memory, went past its CPU or memory limit or gave no valid answer, or another unexpected error |

- **Upgrading.** Files that were `ready` before this release have no converted parts:
  the upgrade's migration puts them back to `uploaded`, and the agent converts them when
  it starts.

## Organizations (Super Admin)

The Super Admin creates organizations, sets their plan limits, deactivates and deletes
them, and sets their data residency policy. These routes are for the Super Admin only
(`403` for everyone else), and they return organization metadata only, never content.
Every change is recorded in the organization's own audit log, so its Org Admins see what
the Super Admin did.

The PWA offers all of this under **Platform → Organizations**. The list shows each
organization's name, status, seat limit, storage quota, data residency and, while a
deletion is pending, the deletion date; there is no budget column in this release. **Create
organization** takes the name, the first Org Admin's email, the seats, the monthly budget
(CHF) and the storage quota (GiB), prefilled with the defaults. Each row's menu offers,
depending on the organization's status, **Edit limits** (a form with **Save limits**, which
saves directly), **Deactivate** / **Reactivate**, **Schedule deletion** / **Cancel
deletion** and the data residency switch (**Require Swiss residency** / **Lift Swiss
residency**); the status and residency actions each ask for a confirmation first. While a
deletion is pending, only **Cancel deletion** is offered. Opening an organization shows its
**organization detail**: the seat usage, the storage used and the number of chats and files
(counts only, never content), and its users. Each user's menu offers what fits their status:
**Deactivate**, **Reactivate**, **Send password reset** (active users of an active
organization) and, for an invited Org Admin of an active organization that has no active
Org Admin yet, **Re-invite** (leave the email blank to resend to the same address, or enter
a new one to replace it).

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
  allowed; it only stops new invitations until seats are free again. `storage_quota`
  caps the total size of the organization's [attachments](#attachments), their original
  files and converted parts; lowering it below what's stored deletes nothing, it only
  refuses new uploads and fails new conversions with `storage_quota_exceeded`.
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
  chats, invitations and queued email, their audit log, the organization itself, and its
  files on disk. What stays is the platform's record of the deletion: an `org.purge` audit event
  with the organization's ID and counts, no names.

  The database enforces the grace period too: a deletion is always open for at least
  7 days and its dates can't change while it's pending, so nothing can purge an
  organization, or its audit log, sooner (see
  [Security Model → Database roles](SECURITY.md#database-roles)).
- **Data residency**: `PATCH /api/platform/orgs/{id}/residency` with `{"enabled": true}`
  or `false`. New organizations start with it on. The change is recorded in the
  organization's audit log, where its Org Admins see it. While it's on, the organization's
  Google and Microsoft tools are disabled and its members can't connect those accounts;
  connections made before are kept but inactive until it's turned off. Its chats also
  reach only a Swiss LLM provider (see
  [Data residency and the provider](#data-residency-and-the-provider)).

An organization's status can only move this way: active ⇄ deactivated, active or
deactivated → pending deletion, pending deletion → deactivated (cancelled). Anything else,
and changing limits or residency while a deletion is pending, answers `409`.

**Users and metadata.** The Super Admin also sees each organization's accounts and usage,
and can help with an account. These routes are for the Super Admin only too. The two reads
change nothing and aren't recorded; every action is recorded in the organization's audit
log, without names or email addresses.

- `GET /api/platform/orgs/{id}/users` lists the organization's active, deactivated and
  invited accounts, oldest first: name (none yet for an invited account), email address,
  role, status, when the account was created and when the user last logged in. Account
  details only, never what the users store.
- `GET /api/platform/orgs/{id}/metadata` returns the seat usage, `seats: {"used",
  "limit"}` (counted like an invitation: active users and pending invitations), the storage
  used in bytes (`storage_used_bytes`), the number of the organization's chats that
  aren't in the trash (a count, never a title), and the number of files (`file_count`).
  Both count every [attachment](#attachments) of the organization, those in the trash
  included, and the storage used is what the quota counts: the original files plus
  their converted parts. A size and a count, never a file name.
- `POST /api/platform/orgs/{id}/users/{user_id}/deactivate` ends every session of the user
  at once and emails them; their chats, connections, notes and settings are kept.
  `.../reactivate` needs a free seat and emails the user a link to log in; it's refused
  while the organization's deletion is pending. An organization always keeps at least one
  active Org Admin, for the Super Admin too: deactivating the last one answers `409` with
  the reason `last_admin`.
- `POST /api/platform/orgs/{id}/users/{user_id}/password-reset` sends the user the same
  email as **Forgot your password?**. The Super Admin never sees the link. The organization
  and the user must be active.
- `POST /api/platform/orgs/{id}/users/{user_id}/invitation` re-invites the organization's
  primary admin: its invited Org Admin, only while the organization is active and has no
  active Org Admin (say the first invitation expired or went to the wrong address). Without
  a body, or with `{}`, it sends the invitation again with a new link: the old link stops
  working and the 72 hours start over. With `{"email": "..."}` it replaces the invited
  account with a new invitation to that address, in the Super Admin's language. A refusal
  (`email_taken`, or `seat_limit` without a free seat) keeps the old invitation and counts
  toward the Super Admin's [refused-send limit](#accounts-and-sessions).

The other `409` reasons are `invalid_status` (the user's or the organization's status
doesn't allow it) and `has_active_admin` (the organization already has an active Org Admin,
who handles its invitations). A user of another organization, or a Super Admin, answers
`404`, like an unknown one. There is no way to set a user's password, read a link or
token, change an existing user's email address, or act as a user.

## Email (SMTP)

admino sends transactional email through **one SMTP account for the whole platform**:
invitations, password resets, account activated/deactivated notices, email change
notices, budget alerts, model deprecation notices and scheduled org deletion notices, for
every organization.
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
- **Compressed, never buffered.** Caddy compresses responses with zstd or gzip, except
  chat event streams, and passes every streamed piece on at once. See
  [Compression and caching](#compression-and-caching).
- **No local model, one process.** The profile never starts the `vllm` container, and the
  agent runs as a single uvicorn process in a single container. Pending confirmations, the
  per-chat run locks and the rate-limit counters live in that process's memory, so don't
  scale it out (see [Chats](#chats)).

**Trying it on a laptop.** With `ADMINO_DOMAIN=localhost`, Caddy uses its own local
certificate authority instead of Let's Encrypt. Check it with curl, e.g.
`curl -k -I https://localhost` and `curl -I http://localhost`. A browser that opens
`https://localhost` may remember the HSTS header and from then on switch
`http://localhost` addresses to HTTPS, including the laptop profile on
`http://localhost:8000`. If that happens, delete the `localhost` entry (in Chrome:
`chrome://net-internals/#hsts`).

## Performance

A chat should feel fast. admino logs where each message's time goes on the server, checks
the server's share against fixed budgets with `make perf`, and documents how to measure
the model's share. The budgets:

| Measure | Budget | Checked by |
| --- | --- | --- |
| Server overhead before the first LLM call (fake LLM) | p95 ≤ 100 ms | `make perf` |
| `GET /api/chats` with 500 chats | p95 ≤ 150 ms | `make perf` |
| SQL statements before the LLM call when you send a message | at most 3 | `make perf`, the timing log |
| End to end, short prompt, chosen model: time to first token | p50 ≤ 3 s | manually, see [Model latency](#model-latency) |

### Timing log

Each request to the three chat routes that run a message writes one `INFO` line on the
`admino.request_timing` logger: `POST /api/chats/{id}/messages` (JSON and streamed),
`POST /api/message` and `POST /api/confirm/{id}`. Every request gets its line, whatever
the outcome, refusals and errors included. No other route writes one.

```
chat timings: request_id=<hex> route=<chat_message|message|confirm> status=<int> db_queries=<n> db_queries_before_llm=<n|-> db_ms=<x.x> llm_start_ms=<x.x|-> llm_first_byte_ms=<x.x|-> llm_ms=<x.x> tool_ms=<x.x> total_ms=<x.x>
```

| Field | Meaning |
| --- | --- |
| `request_id` | The request's `X-Request-ID` (the ID every log line of the request carries), or `-`. |
| `route` | `chat_message`, `message` or `confirm`: a fixed label, never the path (it holds an ID). |
| `status` | The response's HTTP status. A streamed reply is `200`; a request that failed before it answered is `500`. |
| `db_queries` | The SQL statements the request ran, the actions' and the audit log's included. |
| `db_queries_before_llm` | The statements run before the first LLM call. `-` when there was no LLM call. |
| `db_ms` | The statements' summed duration. |
| `llm_start_ms` | Time from the request's arrival to its first LLM call: the server's overhead before the model starts. `-` when there was no LLM call. |
| `llm_first_byte_ms` | Time from the request's arrival to the first thing the provider sent: a streamed reply's first piece, or a JSON reply's first answer. `-` when there was no LLM call. |
| `llm_ms` | The summed duration of the request's LLM calls, retries and their waits included. |
| `tool_ms` | The summed duration of the actions that ran, an approved action included. |
| `total_ms` | Time from the request's arrival to the line. |

- **Times** are milliseconds with one decimal. `llm_start_ms`, `llm_first_byte_ms` and
  `total_ms` count from the request's arrival; `db_ms`, `llm_ms` and `tool_ms` are sums
  over the request.
- **A streamed reply's line** is written once its turn is stored and reported
  (`message_saved`), not when the stream closes. A JSON reply's line is written when the
  response has been sent.
- **Titles don't count.** The automatic title's model call runs after the line is
  written, so it's in none of the numbers.
- **What a statement is.** Each `fetch`, `fetchrow`, `fetchval`, `execute` or
  `executemany` on the app's database pool or one of its connections
  (`database.TimedPool`). `BEGIN`, `COMMIT` and the pool's connection reset aren't
  statements.
- **Content-free.** The line holds the request ID, a fixed route label, the status,
  counts and durations only: no chat, confirmation, user, organization or session ID, no
  message or reply text, no title, tool or model name, no SQL and no error message.

### Statements before the LLM call

When you send a message (`POST /api/chats/{id}/messages`, JSON and streamed), the server
runs exactly 3 SQL statements before its LLM call:

1. the session lookup;
2. the turn setup, in one statement: the organization's tool policy (data residency, the
   service switches and the permission matrix), the languages, timezone and instructions
   the assistant needs, and whether the chat is your own chat, not in the trash;
3. the chat and its latest `max_context_messages` messages, read once the chat's run lock
   is held.

Permission promotions are checked in memory, without a statement. Three things add a
statement, each to one request only:

- a promotion that falls due is written, once;
- the session's `last_seen_at` is updated, at most once a minute;
- a message that finds the platform settings not cached yet (at most the first one after
  a start) reads them once.

`make perf` fails when a send runs more than 3, and in production every send's timing
line shows its count as `db_queries_before_llm`. The older `POST /api/message` keeps its
earlier reads until [#177](https://github.com/ljakupi/admino/issues/177) removes it, and
`POST /api/confirm/{id}` doesn't send a message: neither has this budget, and both still
write their timing line.

### `make perf`

`make perf` checks the server budgets. It's for development only, needs Docker, and isn't
part of `make check` or CI.

```bash
make perf                       # the defaults
PERF_SENDS=400 make perf        # more sends
```

What it does:

1. Starts a throwaway `postgres:16` container on `127.0.0.1` (a free port, random
   passwords), applies the migrations as the owner, and adds one organization, one
   Editor and the platform settings.
2. Runs the app in-process, connected as `admino_app`, with a fake LLM that answers
   after a fixed latency.
3. Creates a chat and sends messages to `POST /api/chats/{id}/messages`, alternating
   JSON and streamed (SSE) sends, after a few warm-up sends that don't count. It reads
   each send's timing line.
4. Fills the user's chats up to 500 and times `GET /api/chats`.
5. Prints p50 and p95 of the server overhead (`llm_start_ms`), of `llm_first_byte_ms`
   and of `GET /api/chats`, and the most statements a send ran before the LLM call, each
   with its budget and `PASS` or `FAIL`. It removes the container in every case.

It measures the steady state: the per-user rate limits of the two measured routes are
lifted for the run (or it would measure the throttle), the session is renewed every 45
seconds so its `last_seen_at` update never falls in a measured send, and the cold
platform settings cache and the chat's first exchange (its title) fall in the warm-up.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PERF_LLM_LATENCY_MS` | 50 | The fake LLM's latency, in milliseconds. |
| `PERF_WARMUP` | 5 | Warm-up sends and list requests that don't count. |
| `PERF_SENDS` | 200 | Measured sends, half JSON and half streamed. |
| `PERF_LISTS` | 200 | Measured `GET /api/chats` requests. |

It fails (exit status `1`) when the p95 overhead is above 100 ms, the p95 of
`GET /api/chats` is above 150 ms, a send ran more than 3 statements before its LLM call,
a send or list request failed, a send wrote no timing line, or the setup failed. The exit
status is `0` when every budget holds, `2` when Docker isn't available or a `PERF_*`
value is invalid, and `130` on Ctrl-C.

The passwords are never printed, and nothing beyond the local container is contacted:
the LLM is a fake and no email is sent. The output holds timings, counts, HTTP statuses
and error codes only.

### Compression and caching

**Compression (production profile).** Caddy compresses every response with zstd, or
gzip for a browser without zstd, except chat event streams (requests with
`Accept: text/event-stream`). A compressor collects bytes before it writes them, which
would hold back the reply's pieces. Caddy also flushes every write from the agent at once
(`flush_interval -1`), so a streamed answer reaches the browser piece by piece and is
never buffered.

`make test-proxy` runs the proxy test: the profile's Caddyfile in the official
`caddy:2.11.4-alpine` image, in front of a stub upstream, checks that a normal response
is compressed and that an event stream arrives uncompressed, frame by frame. It needs
Docker, so it runs on demand; `make check` skips it but always checks the Caddyfile's
text.

**Caching (every profile).** The app sets `Cache-Control` on the PWA files it serves:

| Files | `Cache-Control` | Why |
| --- | --- | --- |
| Hashed assets: files under `assets/` named `<name>-<8-character hash>.<ext>` (the JavaScript, CSS and other files Vite builds) | `public, max-age=31536000, immutable` | A new build gives every changed file a new name, so a file never changes under its name. Browsers keep it for a year without asking again. |
| Everything else: `index.html` (and the page a client route such as `/chat` gets), the service worker (`service-worker.js`, `registerSW.js`, `workbox-*.js`), `manifest.webmanifest`, fonts and icons | `no-cache` | These keep their names from one release to the next. A browser may keep a copy but checks it with the server before each use, so a new release reaches it at the next load. An unchanged file answers `304` without a body, so the check is cheap. |

A missing file (`404`) never gets `immutable`, and API responses aren't touched.

### Model latency

Past the server's overhead, the wait for the first word is the model's. `make ttft`
measures it for the two Infomaniak models. The operator runs it by hand, with the
Infomaniak token in the shell:

```bash
set -a; source .env; set +a     # INFOMANIAK_API_TOKEN (INFOMANIAK_PRODUCT_ID is optional)
make ttft                       # TTFT_RUNS=10 make ttft for more runs
```

- **What it sends.** For `Qwen/Qwen3.5-397B-A17B-FP8` and `Qwen/Qwen3.5-122B-A10B-FP8`,
  a short prompt and a synthetic 20-page document (about 10,000 words, generated by the
  tool, standing in for an attachment until an attachment's text reaches the model with
  [#189](https://github.com/ljakupi/admino/issues/189)), `TTFT_RUNS` times each (5 by
  default, 1 to 50), after one warm-up request per model that doesn't count.
- **How.** Each request is shaped like a chat turn (admino's system prompt and the tool
  definitions of a default organization) and goes through admino's own Infomaniak
  client, streamed, with `reasoning_effort: "none"` and the usual output cap, without
  retries.
- **What it measures.** The time to first token (TTFT): seconds from sending the request
  to the first piece of the answer. Tokens per second: the completion tokens divided by
  the seconds from the first piece to the end of the answer. When the provider reports
  no token count, it's estimated as characters / 4 and marked "est.".
- **What it prints.** The table rows below (the p50 of each model and prompt, with the
  date) and the outcome of the default-model rule. It never prints the token or any
  reply text.
- **Exit status.** `0` when every run succeeded, `1` when a run failed or the rule can't
  be decided, `2` when `INFOMANIAK_API_TOKEN` is missing or `TTFT_RUNS` is invalid, `130`
  on Ctrl-C.

**Results.** Replace these rows with `make ttft`'s output, its date line included:

| Model | Prompt | TTFT p50 | Tokens/s p50 | Runs |
| --- | --- | --- | --- | --- |
| Qwen/Qwen3.5-397B-A17B-FP8 | short prompt | not measured yet | not measured yet | not measured yet |
| Qwen/Qwen3.5-397B-A17B-FP8 | 20-page document | not measured yet | not measured yet | not measured yet |
| Qwen/Qwen3.5-122B-A10B-FP8 | short prompt | not measured yet | not measured yet | not measured yet |
| Qwen/Qwen3.5-122B-A10B-FP8 | 20-page document | not measured yet | not measured yet | not measured yet |

**The default model.** The beta default is `Qwen/Qwen3.5-397B-A17B-FP8`, unless its p50
time to first token for the short prompt is above 3 s. In that case
`Qwen/Qwen3.5-122B-A10B-FP8` becomes the default, and the 397B stays available to the
Super Admin. `make ttft` prints which one the rule picks; the default
(`llm.infomaniak_model`) changes only when the operator sets it. Until the table is
filled in, the default is the 397B.

**End to end.** With the chosen model as the platform's model, the time from sending a
short message to the first word of the reply has a budget of p50 ≤ 3 s. Measure it in the
browser:

1. Open admino, signed in as an Admin or Editor, and open DevTools → **Network**.
2. Send a short message. Select the message request and open its **EventStream** tab.
3. Note the time from sending to the first `delta` event.
4. Do it 5 times and take the median (the third value when sorted).

The current PWA sends its messages as JSON, without streaming (the streaming chat comes
with the new frontend). Until then, send the streamed request from the DevTools
**Console** of a signed-in admino tab. This prints the time to the first `delta` event of
5 sends:

```js
const chat = await (await fetch("/api/chats", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
})).json();
async function firstDelta() {
  const start = performance.now();
  const response = await fetch(`/api/chats/${chat.id}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify({ message: "Suggest three ways to make a weekly team meeting shorter." }),
  });
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let text = "", first = null;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    text += value;
    if (first === null && text.includes("event: delta")) first = performance.now() - start;
  }
  return first === null ? `no delta (status ${response.status})` : `${(first / 1000).toFixed(2)} s`;
}
for (let i = 0; i < 5; i++) console.log(await firstDelta());
```

Each send reads its stream to the end, so every turn is stored as usual (in one new
chat). Take the median of the 5 times.

## Data & storage

PostgreSQL holds the `platform_settings`, `org_settings` and `user_settings`, each organization's `permissions`,
each user's `memory` notes and `oauth_tokens` (one row per user and provider), the
`chats` and their `chat_messages`, the `attachments` of the chats (their metadata), the
`audit_events` audit trail, and the `email_outbox` of queued transactional email. The
attachments' files live on a Docker volume.

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
- **Chats** live in the `chats` and `chat_messages` tables, each chat in its organization
  and with its owner (see [Chats](#chats)). They hold your messages, the assistant's
  replies and the tool results. The assistant's instructions (the platform's rules, the
  organization's and your personal instructions) are never stored. The app can add
  messages but can't edit or delete a single one. Deleting a user deletes their chats, and
  purging an organization deletes all of its chats. A chat in the trash stays stored, only
  marked with `deleted_at`; restoring and purging the trash come with
  [#194](https://github.com/ljakupi/admino/issues/194).
- **Attachments** (see [Attachments](#attachments)). The `attachments` table holds each
  file's chat, owner, the message that carried it, its cleaned original name, type,
  size, the size of its converted parts, status, page count and token estimate. The
  files themselves are on the `admino-attachments` Docker volume, mounted on the agent
  only, at `/app/data/attachments/<organization ID>/<attachment ID>`: owned by `admino`,
  mode 0600 in directories with mode 0700 (the image and the entrypoint create the
  directory). A partial upload is `<attachment ID>.part`; a file's converted parts (see
  [File conversion](#file-conversion)) are in `<attachment ID>.d/`, with the same modes,
  and count toward the storage quota with the original. The original name is in the
  database; on disk it appears only inside a converted PDF's page labels
  (`[<file name> — page N]`), never in a path. The files are **not encrypted at rest**:
  protect the volume like the database (an encrypted disk on the host) and back it up
  with it. `docker volume rm admino-attachments` deletes every file.

  The folder that holds the files, the attachments root, is set by
  `ADMINO_ATTACHMENTS_ROOT`. Unset or empty, it's `/app/data/attachments`, the volume's
  mount point. It must be an absolute path: any other value (a relative path such as
  `data/attachments`) stops admino at startup with `ERROR: ADMINO_ATTACHMENTS_ROOT must
  be an absolute path.` Uploads, downloads, the conversion, the cleanup of unsent files,
  user deletion and the organization purge all use this one folder. Docker Compose sets
  it to `/app/data/attachments` for the agent, so a value in `.env` meant for a native
  run never moves the container's files off the volume. `make run` sets it to
  `data/attachments` in your checkout (see
  [Getting started](getting-started.md#3-run-locally-with-uv)). A root that doesn't exist
  yet is created with mode 0700; an existing one keeps its permissions.

  The root must be a dedicated directory, used by admino only: the cleanup of unsent
  files treats every directory under it whose name is a UUID as an organization's and
  deletes the entries in it that admino doesn't know. Changing the setting doesn't move
  the existing files. Files left under the old root are no longer downloaded, deleted
  with their user or organization, or cleaned up. To change it, stop admino, move the
  whole folder (keeping its permissions) to the new path by hand, then start admino again.
- **The audit log** is the **append-only `audit_events` table**. Every tool call adds one
  row with the chat's ID, the tool, the action, the permission decision, success and
  duration. Arguments, tool output and message text are never stored. Rows are kept for 12
  months by default (6 to 84, a [platform default](#platform-defaults)), and a daily job
  purges older ones. See [Permissions](permissions.md#append-only-audit-log).

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
