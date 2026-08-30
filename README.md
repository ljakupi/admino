# admino

**The AI that works for you, not on you.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
&nbsp;·&nbsp; **v0.1 (Alpha)**

admino is a privacy- and security-first personal AI agent you run yourself. It chats,
reads your mail, calendar, and files, and can take actions on your behalf — but every
action is gated by an **isolated permission engine** that the model cannot see,
influence, or bypass. Nothing happens on your accounts without your say-so.

## Screenshots

| Chat | Settings → Agent |
| --- | --- |
| ![Chat](docs/screenshots/chat.png) | ![Settings → Agent](docs/screenshots/settings-agent.png) |

| Permissions | Critical permissions |
| --- | --- |
| ![Permissions](docs/screenshots/permissions.png) | ![Critical permissions](docs/screenshots/critical-permissions.png) |

## What works today

A chat PWA at `localhost:8000`: send a message, get a response that can call tools.
The tools below are implemented and verified end-to-end; write actions ask you to
confirm first, and a handful of destructive actions are denied by design.

| Tool | Actions | Notes |
| --- | --- | --- |
| **Gmail** | read · list · search | Google OAuth. `send`/`delete` denied by design. |
| **Google Calendar** | read · list · create | `create` asks to confirm. `update`/`delete` denied. |
| **Google Drive** | read · list · search · download | `download` asks to confirm. `delete` denied. |
| **Outlook mail** | read · list · search | Microsoft OAuth. `send`/`delete` denied by design. |
| **Outlook Calendar** | read · list · create | `create` asks to confirm. `update`/`delete` denied. |
| **OneDrive** | read · list · search · download | `download` asks to confirm. `delete` denied. |
| **Files** | read · list · search · write · move | Sandboxed path, no OAuth. `write`/`move` confirm; `overwrite`/`delete` denied. |
| **Memory** | store · recall · list | Persistent notes in PostgreSQL. `delete` denied. |

The Google and Microsoft tools need an OAuth connection — set one up with
`oauth_setup.py`. `files` and `memory` work without connecting any account.

**Not yet implemented:** `documents` (document store) and `search` (web search) are
planned and are **not** in this release — don't expect them to work yet.

## The permission engine

This is the heart of "works for you, not on you." Every tool call the agent wants to
make is checked by a small, **isolated pure function** that receives only the
`(tool, action)` pair — never the conversation, your messages, or the tool arguments.
The agent cannot see the rules, argue with them, or route around them.

- **Default-deny.** Anything not explicitly allowed is denied. Each action resolves to
  one of three states: **allow** (runs immediately), **confirm** (you approve first), or
  **deny** (blocked).
- **Writes are never auto-allowed.** State-changing actions can only be `confirm` or
  `deny` — never `allow`. If config tries to set a write action to `allow`, it is
  downgraded to `confirm`.
- **Critical denials are hardcoded** and cannot be overridden by config or by the agent:
  - **Never** (immutable): every `*.delete` (`files`, `memory`, `google_drive`, both
    calendars, `onedrive`, `documents`, Gmail, Outlook) plus `files.overwrite`.
  - **Deny by default, at most promotable to _confirm_**: `gmail.send`, `outlook.send`,
    and calendar `update`. These stay denied unless you deliberately promote them through
    the Critical Permissions flow (re-authentication + a 5-minute cooldown) — and even
    then they only reach `confirm`, never silent `allow`.
- **Append-only audit log.** Every decision and tool call is written to an append-only
  NDJSON log on disk.

You can review the full matrix on the **Permissions** page and manage promotable
critical permissions under **Settings → Danger zone**.

## LLM providers

admino is designed to run fully local, so **vLLM is the default provider** — but local
vLLM serving isn't implemented yet. On first launch admino boots on vLLM and can't chat
until you switch to a working provider in **Settings → Agent**:

- **Claude (Anthropic)** — opt-in interim provider; needs `ANTHROPIC_API_KEY` on the server.
- **OpenAI** — opt-in interim provider; needs `OPENAI_API_KEY` on the server.

In Settings → Agent, vLLM appears marked *local · coming soon*; pick Claude or OpenAI to
chat right now. Cloud providers send your messages to their servers; everything else —
audit log, memory, documents — stays on your machine.

## Data & storage

PostgreSQL holds four things: `settings`, `permissions`, `memory` notes, and
`oauth_tokens`. OAuth tokens are stored as **encrypted ciphertext only** — the
encryption key lives in the `OAUTH_ENCRYPTION_KEY` environment variable and is never
persisted to the database. The audit log is **append-only NDJSON on disk**.

## Run it

admino defaults to vLLM, which can't serve yet, so the quickest path to a live chat is to
switch to Claude after launch. You need **Python 3.12+**, **Docker** (for Postgres), and
an **Anthropic API key**.

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Configure — copy the sample env and set your Anthropic key
cp .env.example .env
#    edit .env: set ANTHROPIC_API_KEY=...   (PG_PASSWORD already has a dev default)

# 3. Start Postgres, then the agent
make dev-db
make run
```

Open **http://localhost:8000**, then:

1. Click **Skip** on the token prompt — the default `vpn` auth mode needs no token when
   the API is bound to localhost.
2. Open **Settings → Agent** and switch the provider from vLLM to **Claude** (vLLM can't
   chat yet).
3. Type a message and press Enter.
4. The agent responds and may call a tool. Read actions run immediately; write actions
   ask you to confirm; destructive ones are denied.

## Roadmap

- **Local vLLM serving** (Gemma / Qwen) as the default provider — run fully local, no
  cloud calls.
- **Documents** store and **web search** tools.
- End-to-end SSE streaming and a richer health endpoint.

## Contributing

admino is issue-driven: every PR must correspond to an open, approved GitHub issue. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, coding standards, testing gates, and
security rules.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
