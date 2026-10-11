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

To add or update a dependency, see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-or-updating-a-dependency).

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
| `PG_PASSWORD` | Always | The database owner's password, used only to apply migrations. Prefilled with the dev default `changeme`. Change it for any non-local use. |
| `PG_APP_PASSWORD` | Always | The password the app connects with (role `admino_app`). Prefilled with the dev default `changeme-app`. Printable ASCII, different from `PG_PASSWORD`. |
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

# Apply the migrations, then start the agent
make run
```

`make run` first runs `make migrate`: the migrations, applied as the database owner
(`PG_PASSWORD`), which also set the password of the role the app connects as
(`PG_APP_PASSWORD`). It then starts the app with `PG_PASSWORD` removed from its
environment. See [Database roles](SECURITY.md#database-roles).

`make run` keeps uploaded files under `data/attachments` in your checkout (the `data`
folder is git-ignored). It creates the folder if it's missing, sets its mode to 0700
(readable by you only) and passes it to the app as `ADMINO_ATTACHMENTS_ROOT`. To keep
the files somewhere else, export an absolute path to a folder used by admino only
before `make run`, for example
`export ADMINO_ATTACHMENTS_ROOT="$HOME/admino-attachments"`: an exported value wins. A
relative path stops the app at startup. Changing the folder later doesn't move the
files already stored: stop the app and move the folder yourself. See
[Data & storage](configuration.md#data--storage).

The API comes up on **http://localhost:8000**. Continue to
[Create the first Super Admin](#5-create-the-first-super-admin).

Stop the dev database when you're done with `make dev-db-down`.

## 4. Run the whole backend in Docker

This runs the agent and PostgreSQL together. The agent programs an egress firewall at
startup and drops from root to an unprivileged user (see the
[Security Model](SECURITY.md)). Docker Compose reads `.env` directly via `env_file`, so
**no shell export is needed** here.

```bash
cp .env.example .env          # change PG_PASSWORD and PG_APP_PASSWORD; set INFOMANIAK_API_TOKEN
make docker-build             # build the agent image
make start                    # start Postgres, migrations, then the agent (detached); same as make docker-up

make docker-logs              # follow logs
make docker-down              # stop everything
```

**Optional local model.** `make start-local` also starts the vLLM CPU container. On the
first run it downloads the model weights (~8 GB) into a Docker volume, and it skips the
download once they're cached. Then switch the provider to `vllm` (see
[Switching providers](configuration.md#llm-providers)).

The API is published on **http://localhost:8000** (bound to `127.0.0.1` only, by
`docker-compose.local.yml`). No host directory is mounted into the container, so the
agent can't reach files on your machine.

**On a server.** `make start-prod` runs the production profile instead: a Caddy reverse
proxy serves admino over HTTPS at `ADMINO_DOMAIN`, with a Let's Encrypt certificate, and
the agent publishes no port. See
[Production deployment](configuration.md#production-deployment-tls-reverse-proxy).

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
(`make run`), run the same command from your shell with `.env` loaded, after
`make migrate` (or a first `make run`):

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
- The command doesn't run migrations: it connects as the app's role, `admino_app`,
  which can't change the schema. In Docker the `migrate` service applied them before the
  agent started; for local dev, run `make migrate` first.
- The new account is active right away, and the creation is recorded in the audit log
  (`user.activate`, without the email or name). Neither the password nor the email is
  logged.

Then log in at **http://localhost:8000** with that email and password. The Super Admin
only sees the Platform console (**Platform → Organizations** and **Defaults**) and has no
chat; chat needs a member account in an organization.

## 6. Create an organization

Chat happens inside an organization. Create one and invite its first Org Admin from the
command line (the Super Admin can also use **Platform → Organizations → Create
organization**, or `POST /api/platform/orgs`, see
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
- The link works once, for 72 hours. It opens the **Accept invitation** page, where the
  future Org Admin sets their name and password and is logged in as the organization's Org
  Admin. They can then invite everyone else.
- An address that already has an account is refused, and nothing is created.
- With SMTP configured, if the link expires or went to the wrong address, the Super Admin
  can send the invitation again, or to another address, from the organization's detail
  under **Platform → Organizations**, until the organization has an active Org Admin (see [Organizations](configuration.md#organizations-super-admin)).

## 7. Your first chat

1. Open **http://localhost:8000**.
2. Log in with your email address and password. **Forgot password?** on the login page
   emails you a reset link. See
   [Accounts and sessions](configuration.md#accounts-and-sessions).
3. With `INFOMANIAK_API_TOKEN` set, the default Infomaniak model answers right away.
   If the token is missing, admino still starts: the startup log names the variable to
   set, and the chat says the AI model isn't set up yet. To use local **vLLM** (after
   `make start-local`; allow a few
   minutes for the model to load), **Claude** or **OpenAI** (set the matching API key in
   `.env` first), switch the provider in `config.yaml` or as the Super Admin (see
   [Switching providers](configuration.md#llm-providers)).
4. Type a message and press **Enter**.
5. The agent responds and may call a tool. **Read** actions run immediately; **write**
   actions pause for your approval; **destructive** actions are denied. Each organization
   starts from these defaults, and its Org Admins can change them under **Organization**.
   See [Permissions](permissions.md).

## Connect your accounts

`memory` works with no account. The Google and Microsoft tools use each user's own
accounts, which they connect in the app. The operator sets up two things once. First, the
encryption key that protects stored refresh tokens:

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
  desktop applications* platform with redirect URI
  `http://localhost:8000/api/oauth/callback`. Set `MICROSOFT_CLIENT_ID` and
  `MICROSOFT_CLIENT_SECRET`.

admino sends `http://<server.host>:<server.port>/api/oauth/callback` as the redirect URI
(`localhost` when the host is `0.0.0.0`). When admino runs behind another address, set
`OAUTH_REDIRECT_URI` in `.env` to the callback address you registered with the provider.

From then on, each user connects their own accounts:

1. Log in as an Org Admin or Editor and open the **Tools** page (**My connections**).
2. Click **Connect** on the Google or Microsoft card and grant consent at the provider.
   Finish within 10 minutes, in the same browser; otherwise the Tools page says the
   session expired and you click **Connect** again.
3. You're back on the Tools page with the account connected. Each service shows whether
   it's active, turned off by your organization, or restricted by data residency.

The **refresh token is encrypted with your Fernet key and stored in PostgreSQL** for your
user only. Access tokens are kept in memory only and never persisted. The agent uses your
connection in your own chats only, never in a colleague's. **Disconnect** on the same card
revokes the token at the provider and deletes it.

- The Super Admin can't chat and has no connections.
- An Org Admin turns services on or off for the whole organization under
  **Organization → Settings**, in **Tools and permissions**.
- When your organization's data residency policy is on, the Google and Microsoft tools are
  disabled and connecting an account is refused. Connections made before are kept but
  inactive; you can still disconnect them.

## How environment loading differs (local vs Docker)

This trips people up, so it's worth stating plainly:

| | Local dev (`make run`) | Docker (`make docker-up`) |
| --- | --- | --- |
| Reads `.env`? | **No** — reads the shell environment + `config/config.yaml` | **Yes** — Compose loads it via `env_file` |
| Getting secrets in | `set -a; source .env; set +a` (or `export` them) | Just edit `.env` |
| PostgreSQL | Container via `make dev-db`, published on `127.0.0.1:5432` | Container on the internal network, not published |
| Uploaded files | `data/attachments` in the checkout (`ADMINO_ATTACHMENTS_ROOT`) | The `admino-attachments` volume, whatever `.env` says |

## Upgrading from the single-tenant version

admino is becoming a multi-tenant platform, with organizations and user accounts in three
roles: Super Admin, Org Admin and Editor. **The upgrade starts from an empty platform.**

- **Add `PG_APP_PASSWORD` to `.env` before you upgrade** (see `.env.example`). The app
  now connects as the non-superuser role `admino_app`; the `migrate` service creates it
  on your existing database at the next start and gives it that password. Keep
  `PG_PASSWORD` as it is: it's the password your database volume was created with.
- Migrations run on startup against your existing database. The first tenancy migration
  only adds the (empty) `organizations` and `users` tables, so nothing changes until login
  with user accounts arrives.
- Later migrations move settings, tool permissions, memory notes and Google/Microsoft
  connections from the single install to organizations and users. They **drop the existing
  rows** instead of converting them: the install-wide Google and Microsoft tokens and every
  memory note are deleted, never handed to some user. After that upgrade you set your
  settings and tool permissions again, and each user reconnects their own accounts on the
  **Tools** page.
- Some earlier versions created a "Default organization" to hold the audit events of tool
  calls made before login existed. The upgrade deletes it and its audit events
  automatically, so an upgraded install starts with no organization, like a new one.
- Upgrading to this version retires the read-only member role. Accounts that held it are
  deactivated, which ends their sessions, and stored as Editors; their pending invitations
  are revoked. Each change is recorded in the organization's audit log with the `system`
  actor: `user.deactivate` with the `reason` `viewer_retired`, and `invitation.revoke`. No
  email is sent. Such an account keeps its connections and data, as with any deactivation.
  Reactivation restores the stored role, so an Org Admin or the Super Admin who
  reactivates it grants it the Editor role.

## Quality gates (for contributors)

admino is test-first. Before pushing, run the exact gate CI runs:

```bash
make check      # lint + format-check + typecheck + tests (coverage ≥ 90%)
```

These run on demand, not in CI (see [Configuration → Performance](configuration.md#performance)):

```bash
make perf         # server budgets against a throwaway Postgres and a fake LLM (needs Docker)
make test-proxy   # the production Caddyfile in the caddy image: compression, unbuffered streams (needs Docker)
make ttft         # time to first token of the Infomaniak models (reads INFOMANIAK_API_TOKEN from .env)
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

- **The chat says "This AI model isn't set up yet."** (error code `not_configured`) The
  provider's key or token is missing or was rejected. For Infomaniak, add the token to
  `.env` (see [Create the Infomaniak token](#create-the-infomaniak-token)) and restart; the
  startup log names what's missing. If it's set, check it has the `ai-tools` scope. If the
  startup log asks for `INFOMANIAK_PRODUCT_ID`, your token sees several AI products: set
  the one to use.
- **The chat says "The AI service is temporarily unavailable."** (error code
  `provider_unavailable`) With vLLM, the container isn't ready yet. Either run
  `make start-local` and wait a few minutes for the model to load (CPU inference takes time
  on first start), or switch back to Infomaniak (see
  [Switching providers](configuration.md#llm-providers)). admino already retried the
  request a few times (see [LLM errors and retries](configuration.md#llm-errors-and-retries)).
- **The chat says the data residency policy doesn't allow the current AI model.** (error
  code `residency_blocked`) Your organization's data residency policy is on and the active
  provider is Claude or OpenAI. The Super Admin switches back to Infomaniak or vLLM, or
  turns the organization's policy off (see
  [Data residency and the provider](configuration.md#data-residency-and-the-provider)).
- **`PG_APP_PASSWORD environment variable is required but not set`** (or the migration
  says `PG_PASSWORD` or `PG_APP_PASSWORD` is missing). Set both in `.env`. For local dev,
  load `.env` into your shell first: `set -a; source .env; set +a`.
- **The database schema is not up to date.** The app found pending migrations and
  doesn't run them itself. In Docker, check the `migrate` service's log
  (`docker compose logs migrate`); for local dev, run `make migrate`.
- **`Migration version 0031 is used by more than one file: 0031_a.sql, 0031_b.sql.`**
  Two migration files in `src/admino/migrations/` share one number (for example after
  merging two branches that each added one). The migrate step stops before it applies
  anything and exits with 1; its log names the number and the files, never their
  contents. The app refuses to start the same way, but its own log says only
  `Database startup failed (DuplicateMigrationVersionError)`, followed by the usual
  hint to check the database settings and the migrations: read the migrate step's log
  (`docker compose logs migrate`, or `make migrate`) for the number and the files.
  Give the next free number to the file the database hasn't applied: its `_migrations`
  table records, for each number, the `name` of the file it applied
  (`SELECT name FROM _migrations WHERE version = 31`). Renumbering the applied one
  would apply it again and leave the other skipped; on a new database, where neither
  is applied, either one will do. Then run `make migrate` again.
- **A tool says the account isn't connected.** Open the **Tools** page and click
  **Connect** for that provider (see [Connect your accounts](#connect-your-accounts)).
  Connections are per user: connecting your account doesn't connect a colleague's. If
  connecting fails, check that `OAUTH_ENCRYPTION_KEY` and the client credentials are set.
  If it's refused, your organization's data residency policy may be on.
- **The container won't start / egress errors.** By default the agent fails closed if it
  can't program its egress firewall. See the [Security Model](SECURITY.md) and the
  `REQUIRE_EGRESS_WHITELIST` note in [`.env.example`](../.env.example).

---

Next: **[Permissions](permissions.md)** · **[Configuration](configuration.md)** ·
**[Security Model](SECURITY.md)** · [← Docs home](README.md)
