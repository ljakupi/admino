# Getting Started

This guide takes you from a clean checkout to a working chat, then shows how to connect
your Google/Microsoft accounts so admino can use its mail, calendar, and drive tools.

- [Requirements](#requirements)
- [1. Install](#1-install)
- [2. Configure](#2-configure)
- [3. Run locally (with uv)](#3-run-locally-with-uv)
- [4. Run the whole backend in Docker](#4-run-the-whole-backend-in-docker)
- [5. Create the first Super Admin](#5-create-the-first-super-admin)
- [6. Create an organization](#6-create-an-organization)
- [7. Your first chat](#7-your-first-chat)
- [Connect your accounts](#connect-your-accounts)
- [How environment loading differs (local vs Docker)](#how-environment-loading-differs-local-vs-docker)
- [Upgrading from the single-tenant version](#upgrading-from-the-single-tenant-version)
- [Quality gates (for contributors)](#quality-gates-for-contributors)
- [Troubleshooting](#troubleshooting)

## Requirements

| | |
| --- | --- |
| **Python 3.12+** | admino targets the current CPython. |
| **[uv](https://docs.astral.sh/uv/)** | Package & virtualenv manager. Install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Docker + Docker Compose** | Runs PostgreSQL (local dev) or the whole backend. |
| **LLM backend** | **Default:** an [Infomaniak AI Services](https://www.infomaniak.com/en/hosting/ai-services) API token with the `ai-tools` scope, set as `INFOMANIAK_API_TOKEN` in `.env` (see [Create the Infomaniak token](#create-the-infomaniak-token)). **Optional local model:** `make start-local` runs vLLM on CPU; Docker Desktop needs ~12–16 GB RAM. **Optional cloud:** an [Anthropic](https://console.anthropic.com/) or [OpenAI](https://platform.openai.com/api-keys) key. |
| **Google / Microsoft OAuth apps** *(optional)* | Only needed to enable the mail, calendar, and drive tools. See [Connect your accounts](#connect-your-accounts). |

admino is laptop-first (macOS / Linux). A VPS deployment is possible but out of scope for
this quick start.

## 1. Install

`uv` reads `pyproject.toml` + `uv.lock` and builds an isolated virtualenv in `.venv`:

```bash
uv sync                       # base deps: Infomaniak (default), vLLM and OpenAI providers
# or:
uv sync --extra anthropic     # base deps + the Claude provider
# or, for contributors (all providers + test/lint/type tooling):
uv sync --extra dev
```

The `openai` SDK is a core dependency because the default provider (Infomaniak) and the
local vLLM provider speak the OpenAI-compatible API through it. The Anthropic SDK stays an
**optional extra**. Activate the environment:

```bash
source .venv/bin/activate
```

## 2. Configure

Copy the sample environment file and fill in what you need:

```bash
cp .env.example .env
```

Key variables by use case:

| Variable | Needed for | Notes |
| --- | --- | --- |
| `PG_PASSWORD` | Always | Prefilled with the dev default `changeme`. Change it for any non-local use. |
| `INFOMANIAK_API_TOKEN` | Chatting via Infomaniak (default) | Required for the default provider. See [Create the Infomaniak token](#create-the-infomaniak-token). |
| `INFOMANIAK_PRODUCT_ID` | Infomaniak, several AI products | Optional. Discovered at startup when the token sees exactly one AI Tools product. |
| `HF_TOKEN` | `make vllm-pull` (gated models only) | Optional — only if the model repo is private/gated. Never used at runtime. |
| `VLLM_MODEL` | Local vLLM (if overriding the default) | Defaults to `Qwen/Qwen3-4B-Instruct-2507`. |
| `ANTHROPIC_API_KEY` | Chatting via Claude | Uncomment and set it. Get one at <https://console.anthropic.com/>. |
| `OPENAI_API_KEY` | Chatting via OpenAI | Alternative to Anthropic. |

### Create the Infomaniak token

1. In the [Infomaniak Manager](https://manager.infomaniak.com/), open **AI Tools** and
   create (or open) your AI Tools product. The service bills per token; set a spending
   limit there if you want one.
2. Go to **API tokens** (<https://manager.infomaniak.com/v3/ng/accounts/token/list>) and
   create a token with the **`ai-tools`** scope.
3. Put it in `.env` as `INFOMANIAK_API_TOKEN=…`. It stays on the server: admino never logs
   it or sends it to the browser.
4. `INFOMANIAK_PRODUCT_ID` is optional. At startup admino looks it up with
   `GET https://api.infomaniak.com/1/ai`. If your token sees several AI products, the
   startup log and the chat ask you to set `INFOMANIAK_PRODUCT_ID` to the one to use
   (the `product_id` from that same call, or the number in the product's Manager URL).

The default model is `Qwen/Qwen3.5-397B-A17B-FP8`. Processing happens in Switzerland,
and Infomaniak doesn't record queries or use them for training. See
[Configuration → Infomaniak](configuration.md#infomaniak-ai-services-default).

To also enable the mail/calendar/drive tools, set the OAuth and encryption variables
described in [Connect your accounts](#connect-your-accounts). Every variable is documented
inline in [`.env.example`](../.env.example).

> **Secrets never touch `config.yaml`.** API keys, OAuth client secrets, the encryption
> key, and the auth token are read from the environment **only** — see
> [Configuration](configuration.md).

## 3. Run locally (with uv)

Local dev runs the Python app natively (fast reloads) and PostgreSQL in Docker.

> ⚠️ **`make run` reads your shell environment, not `.env`.** Load `.env` into your shell
> first, or export the variables yourself.

```bash
# Load .env into the current shell (exports every KEY=value line)
set -a; source .env; set +a

# Start PostgreSQL (Docker) — the dev overlay publishes it on 127.0.0.1:5432
make dev-db

# Start the agent
make run
```

The API comes up on **http://localhost:8000**. Continue to
[Create the first Super Admin](#5-create-the-first-super-admin).

Stop the dev database when you're done with `make dev-db-down`.

## 4. Run the whole backend in Docker

This runs the agent and PostgreSQL together. The agent programs an egress firewall at
startup and drops from root to an unprivileged user (see the
[Security Model](SECURITY.md)). Docker Compose reads `.env` directly via `env_file`, so
**no shell export is needed** here.

```bash
cp .env.example .env          # change PG_PASSWORD; set INFOMANIAK_API_TOKEN
make docker-build             # build the agent image
make start                    # start agent + Postgres (detached); same as make docker-up

make docker-logs              # follow logs
make docker-down              # stop everything
```

**Optional local model.** `make start-local` also starts the vLLM CPU container. On the
first run it downloads the model weights (~8 GB) into a Docker volume, and it skips the
download once they're cached. Then pick **vLLM** in **Settings → Agent**.

The API is published on **http://localhost:8000** (bound to `127.0.0.1` only). No host
directory is mounted into the container, so the agent can't reach files on your machine.

> **Docker Desktop memory (`make start-local` only):** the vLLM CPU container needs ~8 GB for the model plus KV
> cache headroom. Allocate **~12–16 GB** in Docker Desktop → Settings → Resources →
> Memory (the default 8 GB is not enough).

## 5. Create the first Super Admin

admino has no public sign-up. The first account is a **Super Admin**, created from the
command line. The Super Admin runs the platform and belongs to no organization.

With the Docker stack running (`make start`):

```bash
make create-superadmin EMAIL=you@example.ch NAME='Your Name'
```

This runs `python -m admino.admin_cli create-superadmin --email … --name …` inside the
agent container (`docker compose exec`, as the unprivileged `admino` user). For local dev
(`make run`), run the same command from your shell with `.env` loaded:

```bash
python -m admino.admin_cli create-superadmin --email you@example.ch --name 'Your Name'
```

- The command asks for the password twice on the terminal. It never takes the password as
  an argument, so it doesn't end up in your shell history or the process list. Without an
  interactive terminal (e.g. `docker compose exec -T`, or input piped in) it refuses to run.
- The password follows the [password policy](configuration.md#accounts-and-sessions): 12
  to 128 characters, not your email address, and not one of the 100,000 most common
  passwords. A weak password or a typo in the confirmation asks again, up to three times.
- An email address that's already taken is refused, whatever its capitalization.
- The command applies pending database migrations first, so it also works on a fresh
  database before the agent's first start.
- The new account is active right away, and the creation is recorded in the audit log
  (`user.activate`, without the email or name). Neither the password nor the email is
  logged.

Then log in at **http://localhost:8000** with that email and password. The Super Admin
sees the platform only and has no chat; chat needs a member account in an organization.

## 6. Create an organization

Chat happens inside an organization. Create one and invite its first Org Admin from the
command line (the Super Admin can also do it with `POST /api/platform/orgs`, see
[Organizations](configuration.md#organizations-super-admin)):

```bash
make create-org NAME='Treuhand Muster AG' ADMIN_EMAIL=admin@example.ch
```

This runs `python -m admino.admin_cli create-org --name … --admin-email …` inside the agent
container. For local dev (`make run`), run the same command from your shell with `.env`
loaded. The plan limits default to **10 seats, CHF 100 a month and 10 GiB of storage**, and
the invitation email is in English; set them with `--seats`, `--budget-chf`,
`--storage-quota-gib` and `--language de|fr|en` (see `create-org --help`).

- The command prints the new organization's ID.
- **With SMTP configured** (see [Email](configuration.md#email-smtp)), the invitation is
  emailed to the address you gave.
- **Without SMTP**, nothing is emailed. The command prints the one-time invitation link on
  your terminal instead; it isn't logged or stored anywhere else. Give it to the future Org
  Admin. The command refuses to run when its output doesn't go to a terminal (for example
  when piped into a file), so the link can't end up in a file.
- The link works once, for 72 hours. Accepting it with a name and a password makes that
  person the organization's Org Admin, who can then invite everyone else.
- An address that already has an account is refused, and nothing is created.

## 7. Your first chat

1. Open **http://localhost:8000**.
2. Log in with your email address and password. See
   [Accounts and sessions](configuration.md#accounts-and-sessions).
3. With `INFOMANIAK_API_TOKEN` set, the default Infomaniak model answers right away.
   If the token is missing, admino still starts and the chat replies that Infomaniak
   isn't configured. **Settings → Agent** switches to local **vLLM** (after
   `make start-local`; allow a few minutes for the model to load), **Claude** or
   **OpenAI** (set the matching API key in `.env` first).
4. Type a message and press **Enter**.
5. The agent responds and may call a tool. **Read** actions run immediately; **write**
   actions pause for your approval; **destructive** actions are denied. See
   [Permissions](permissions.md).

## Connect your accounts

`files` and `memory` work with no account. The Google and Microsoft tools need a one-time
OAuth consent. First, set the encryption key that protects stored refresh tokens:

```bash
# Generate a Fernet key and add it to .env as OAUTH_ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then register an OAuth app with the provider and put its client ID/secret in `.env`:

- **Google** (Gmail, Calendar, Drive) — create an *OAuth 2.0 Client ID* of type **Desktop
  app** at <https://console.cloud.google.com/apis/credentials>. Set `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`.
- **Microsoft** (Outlook, Calendar, OneDrive) — register an app at
  <https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps> using the *Mobile and
  desktop applications* platform with redirect URI `http://localhost:8000/oauth/callback`.
  Set `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`.

Run the one-time consent flow (make sure the variables above are loaded in your shell):

```bash
python -m admino.oauth_setup google       # or: microsoft
```

The script prints a consent URL, you paste back the authorization code, and the resulting
**refresh token is encrypted with your Fernet key and stored in PostgreSQL** — the access
token obtained during setup is discarded and never persisted.

## How environment loading differs (local vs Docker)

This trips people up, so it's worth stating plainly:

| | Local dev (`make run`) | Docker (`make docker-up`) |
| --- | --- | --- |
| Reads `.env`? | **No** — reads the shell environment + `config/config.yaml` | **Yes** — Compose loads it via `env_file` |
| Getting secrets in | `set -a; source .env; set +a` (or `export` them) | Just edit `.env` |
| PostgreSQL | Container via `make dev-db`, published on `127.0.0.1:5432` | Container on the internal network, not published |

## Upgrading from the single-tenant version

admino is becoming a multi-tenant platform, with organizations and user accounts in four
roles: Super Admin, Org Admin, Editor and Viewer. **The upgrade starts from an empty
platform.**

- Migrations run on startup against your existing database. The first tenancy migration
  only adds the (empty) `organizations` and `users` tables, so nothing changes until login
  with user accounts arrives.
- Later migrations move settings, tool permissions, memory notes and Google/Microsoft
  connections from the single install to organizations and users. They **drop the existing
  rows** instead of converting them. After that upgrade you set your settings and tool
  permissions again and reconnect your accounts.
- Some earlier versions created a "Default organization" to hold the audit events of tool
  calls made before login existed. The upgrade deletes it and its audit events
  automatically, so an upgraded install starts with no organization, like a new one.

## Quality gates (for contributors)

admino is test-first. Before pushing, run the exact gate CI runs:

```bash
make check      # lint + format-check + typecheck + tests (coverage ≥ 90%)
```

For frontend changes, from `static-src/`:

```bash
npm run check:i18n   # en/de/fr translation catalogs match
npm run typecheck
npm run test
npm run build
```

The PWA is translated into English, German and French; every UI string lives in
`static-src/src/i18n/locales/`. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rules.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full workflow, coding standards, and
security rules.

## Troubleshooting

- **"Infomaniak isn't configured; set INFOMANIAK_API_TOKEN".** Add the token to `.env`
  (see [Create the Infomaniak token](#create-the-infomaniak-token)) and restart. If the chat
  says the token was rejected, check it has the `ai-tools` scope. If it asks for
  `INFOMANIAK_PRODUCT_ID`, your token sees several AI products: set the one to use.
- **"admino replies with 'model unavailable' or 'model starting'."** The vLLM container
  isn't ready yet. Either run `make start-local` and wait a few minutes for the model to
  load (CPU inference takes time on first start), or switch back to Infomaniak in
  **Settings → Agent**.
- **`PG_PASSWORD environment variable is required but not set`.** For local dev, load
  `.env` into your shell first: `set -a; source .env; set +a`.
- **A tool says the account isn't connected.** Run `python -m admino.oauth_setup <google|microsoft>`
  with `OAUTH_ENCRYPTION_KEY` and the client credentials loaded — see
  [Connect your accounts](#connect-your-accounts).
- **The container won't start / egress errors.** By default the agent fails closed if it
  can't program its egress firewall. See the [Security Model](SECURITY.md) and the
  `REQUIRE_EGRESS_WHITELIST` note in [`.env.example`](../.env.example).

---

Next: **[Permissions](permissions.md)** · **[Configuration](configuration.md)** ·
**[Security Model](SECURITY.md)** · [← Docs home](README.md)
