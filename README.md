# admino

**The AI that works for you and not on you.**

**v0.1 (Alpha) — MVP**

## What admino is

admino is a privacy- and security-first personal AI agent. Every tool action the
agent wants to take is gated by an **isolated permission engine** — a pure function
that receives only the `(tool, action)` pair and never sees the model's context, so
the agent cannot see, influence, or bypass it.

The engine is **default-deny**: anything not explicitly allowed is denied.
**Hardcoded denials cannot be overridden** by config or by the agent, and write
actions are never auto-allowed — they resolve to *confirm* or *deny* only. That is
what "works for you, not on you" means: admino cannot take uncontrolled or
un-permitted actions on your behalf.

## What's available today

- **Chat PWA** at `localhost:8000` — send a message, get a response that may call tools.
- **LLM provider:** **Anthropic** (default). OpenAI also works (opt-in).
- **Tools:** `memory`, `files`, `gmail`, `google_calendar`, `google_drive`,
  `outlook`, `outlook_calendar`, `onedrive`. The Google/Microsoft tools require an
  OAuth connection — set one up with `oauth_setup.py`.
- **Permission engine** gating every action, plus an **append-only audit log**.

## Data & storage

PostgreSQL holds four things: `settings`, `permissions`, `memory` notes, and
`oauth_tokens`. OAuth tokens are stored as **encrypted ciphertext only** — the
encryption key lives in the `OAUTH_ENCRYPTION_KEY` environment variable and is never
persisted to the database. The audit log is **append-only NDJSON on disk**.

## How to run

The minimal path uses Anthropic and ends at a live chat on `localhost:8000`. You need
**Python 3.12+**, **Docker** (for Postgres), and an **Anthropic API key**.

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

Open **http://localhost:8000**.

## What to expect

1. The PWA loads — click **Skip** on the token prompt (the default `vpn` auth mode
   needs no token when the API is bound to localhost).
2. Type a message and press Enter.
3. The agent responds, and may call one of the tools above (gated by the permission
   engine — write actions ask you to confirm first).

## Upcoming

- **Local SLM serving via vLLM** (Gemma / Qwen) — planned as the eventual **default**
  provider, so admino can run fully local with no cloud calls.
- Document store and web-search tools.
- End-to-end SSE streaming and a richer health endpoint.

## Contributing

admino is issue-driven: every PR must correspond to an open, approved GitHub issue.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, coding standards, testing
gates, and security rules.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
