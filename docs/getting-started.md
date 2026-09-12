# Getting Started

This guide takes you from a clean checkout to a working chat, then shows how to connect
your Google/Microsoft accounts so admino can use its mail, calendar, and drive tools.

- [Requirements](#requirements)
- [1. Install](#1-install)
- [2. Configure](#2-configure)
- [3. Run locally (with uv)](#3-run-locally-with-uv)
- [4. Run the whole backend in Docker](#4-run-the-whole-backend-in-docker)
- [5. Your first chat](#5-your-first-chat)
- [Connect your accounts](#connect-your-accounts)
- [How environment loading differs (local vs Docker)](#how-environment-loading-differs-local-vs-docker)
- [Quality gates (for contributors)](#quality-gates-for-contributors)
- [Troubleshooting](#troubleshooting)

## Requirements

| | |
| --- | --- |
| **Python 3.12+** | admino targets the current CPython. |
| **[uv](https://docs.astral.sh/uv/)** | Package & virtualenv manager. Install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Docker + Docker Compose** | Runs PostgreSQL (local dev) or the whole backend. |
| **LLM backend (one of)** | **Local (Apple Silicon, macOS 15+):** install `vllm-metal`, then `make vllm-pull` + `make vllm-up` — no API key needed. **Cloud:** an [Anthropic](https://console.anthropic.com/) or [OpenAI](https://platform.openai.com/api-keys) key, set in `.env`. |
| **Google / Microsoft OAuth apps** *(optional)* | Only needed to enable the mail, calendar, and drive tools. See [Connect your accounts](#connect-your-accounts). |

admino is laptop-first (macOS / Linux). A VPS deployment is possible but out of scope for
this quick start.

## 1. Install

`uv` reads `pyproject.toml` + `uv.lock` and builds an isolated virtualenv in `.venv`:

```bash
uv sync --extra anthropic     # base deps + the Claude provider
# or:
uv sync --extra openai        # base deps + the OpenAI provider
# or, for contributors (both providers + test/lint/type tooling):
uv sync --extra dev
```

The base install is deliberately minimal — the Anthropic and OpenAI SDKs are **optional
extras** so you only pull in the provider you actually use. Activate the environment:

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
| `HF_TOKEN` | `make vllm-pull` (gated models only) | Optional — only if the model repo is private/gated. Never used at runtime. |
| `VLLM_MODEL` | Local vLLM (if overriding the default) | Defaults to `mlx-community/gemma-4-12B-it-4bit`. |
| `ANTHROPIC_API_KEY` | Chatting via Claude | Uncomment and set it. Get one at <https://console.anthropic.com/>. |
| `OPENAI_API_KEY` | Chatting via OpenAI | Alternative to Anthropic. |

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
[Your first chat](#5-your-first-chat).

Stop the dev database when you're done with `make dev-db-down`.

## 4. Run the whole backend in Docker

This runs the agent **and** PostgreSQL in containers. The agent container programs an
egress firewall at startup and drops from root to an unprivileged user (see the
[Security Model](SECURITY.md)). Docker Compose reads `.env` directly via `env_file`, so
**no shell export is needed** here.

```bash
cp .env.example .env          # set ANTHROPIC_API_KEY and change PG_PASSWORD
make docker-build             # build the image
make docker-up                # start agent + Postgres (detached)

make docker-logs              # follow logs
make docker-down              # stop everything
```

The API is published on **http://localhost:8000** (bound to `127.0.0.1` only). The agent
can read and write files under `~/Downloads/admino` on your host, which is mounted into
the container at `/app/documents`. Nothing outside that directory is reachable.

## 5. Your first chat

1. Open **http://localhost:8000**.
2. On the token prompt, click **Skip** — the default `vpn` auth mode needs no token when
   the API is bound to localhost. (See [auth modes](configuration.md#authentication-modes).)
3. If you ran `make vllm-up`, the local model loads automatically — allow 1-2 minutes,
   then type a message. If you haven't started vLLM yet, open **Settings → Agent** and
   switch to **Claude** or **OpenAI** (set the matching API key in `.env` first).
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

## Quality gates (for contributors)

admino is test-first. Before pushing, run the exact gate CI runs:

```bash
make check      # lint + format-check + typecheck + tests (coverage ≥ 90%)
```

For frontend changes, from `static-src/`:

```bash
npm run typecheck
npm run build
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full workflow, coding standards, and
security rules.

## Troubleshooting

- **"admino replies with 'model unavailable' or 'model starting'."** The local vLLM
  server isn't running yet. Either run `make vllm-up` (Apple Silicon) and wait 1-2
  minutes for the 12B model to load, or switch to a cloud provider in **Settings → Agent**
  and set the matching API key in `.env`.
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
