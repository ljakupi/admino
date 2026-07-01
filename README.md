# admino

Local-only, security-first personal AI agent. Python 3.12+, FastAPI, Pydantic v2, Docker Compose deployment. LLM inference via **Ollama** (default, local), **vLLM** (local, GPU), **Anthropic Claude**, or **OpenAI** — provider is selected via `llm.provider` in `config.yaml`.

## How to Run

You're in your IDE terminal, the repo is cloned, and you want the app running. Here's what to do.

### Prerequisites

You need **Python 3.12+** and one LLM backend:

- **Ollama** (default, local, recommended for privacy) — `brew install ollama`
- **vLLM** (local, GPU required) — runs as a Docker overlay
- **Anthropic Claude** (opt-in, cloud) — `ANTHROPIC_API_KEY` env var
- **OpenAI** (opt-in, cloud) — `OPENAI_API_KEY` env var

### Quick start (local dev, recommended)

Run these commands from the project root:

```bash
# 1. Install Python dependencies
pip install -e ".[dev]"

# 2. Start Ollama and pull the model (one-time, ~8-10 GB download)
ollama serve &               # skip if Ollama is already running
ollama pull gemma4:12b

# 3. Create data directories + the single sandboxed files dir
mkdir -p data/postgres data/logs ~/Downloads/admino

# 4. Start the agent
make run
```

Open **http://localhost:8000** in your browser. Done.

The config defaults in `config/config.yaml` currently target Anthropic (`llm.provider: "anthropic"`) since that's what's been exercised most recently in development. To switch to a local Ollama running on your laptop, change `llm.provider` to `"ollama"` and uncomment `ollama_url: "http://localhost:11434"`. VPN auth mode and relative data paths work out of the box either way.

### What happens at startup

1. `main.py` loads `config/config.yaml` and builds the default permission ruleset from `admino.permissions.DEFAULT_PERMISSIONS`
2. Opens the audit logger at `data/logs/audit.ndjson`
3. Connects to PostgreSQL (via the `PG_*` env vars), runs migrations, and seeds settings/permissions (the defaults seed an empty DB only — the DB is authoritative thereafter); configures the files tool (allowed paths from config)
4. Instantiates the LLM client for the configured `llm.provider` (Ollama / Anthropic / OpenAI), registers all tool handlers, freezes the registry
5. Starts uvicorn on `0.0.0.0:8000` (single worker)

### What to expect in the browser

1. The PWA loads — click **Skip** on the token prompt (VPN auth mode needs no token)
2. Type a message and press Enter
3. The agent sends your message to the configured LLM provider, which may respond with tool calls
4. Implemented tools: `memory`, `files`, `gmail`, `google_calendar`, `google_drive`, `outlook`, `outlook_calendar`, and `onedrive` (the Google/Microsoft tools require an OAuth connection — see `oauth_setup.py`)

### Docker mode (optional)

admino uses a base + overlay compose layout. The base `docker-compose.yml` defines the `agent` container only. Local LLM backends live in provider-specific overlay files (`docker-compose.ollama.yml`, `docker-compose.vllm.yml`) that are merged via `make docker-up BACKEND=<name>`.

**Agent in Docker + native Ollama** (keeps Metal GPU acceleration):

```bash
ollama serve &
ollama pull gemma4:12b
cp .env.example .env
# Edit config/config.yaml: llm.provider: "ollama", ollama_url: "http://host.docker.internal:11434"
mkdir -p data/postgres data/logs ~/Downloads/admino
make docker-build && make docker-up
```

**Full Docker with Ollama** (agent + Ollama in containers, for VPS):

```bash
cp .env.example .env
# Defaults already point at http://local-llm:11434 — no edits needed.
mkdir -p data/postgres data/logs ~/Downloads/admino
make docker-build BACKEND=ollama
make docker-up BACKEND=ollama
docker compose exec local-llm ollama pull gemma4:12b
```

**Full Docker with vLLM** (agent + vLLM, GPU required):

```bash
cp .env.example .env
# Edit config/config.yaml: set llm.provider: "openai" and openai_base_url: "http://local-llm:8000/v1"
mkdir -p data/postgres data/logs data/hf-cache ~/Downloads/admino
make docker-build BACKEND=vllm
make docker-up BACKEND=vllm
```

**Full Docker with a proprietary provider** (Anthropic / OpenAI — no local LLM container):

```bash
cp .env.example .env
# Set ANTHROPIC_API_KEY (or OPENAI_API_KEY) in .env.
# Set llm.provider in config/config.yaml to "anthropic" or "openai".
mkdir -p data/postgres data/logs ~/Downloads/admino
make docker-build
make docker-up
```

All four modes serve at **http://localhost:8000**. The agent inside the container always reaches the local LLM (when present) at the provider-agnostic hostname `http://local-llm:PORT` — swapping backends means swapping the `BACKEND` variable, not editing internal service names.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `Connection refused` on port 8000 | Is the agent running? `make run` or `docker compose ps` |
| `Connection refused` to Ollama | Start it: `ollama serve` — verify with `ollama list`. In Docker mode with `BACKEND=ollama`, check `docker compose ps` and confirm `local-llm` is healthy. |
| Slow first response | Normal — first inference loads the model into GPU memory |
| `Model not found` | `ollama pull gemma4:12b` (native) or `docker compose exec local-llm ollama pull gemma4:12b` (Docker) |
| `ANTHROPIC_API_KEY not set` | Export it in `.env` (copied from `.env.example`). Required when `llm.provider: "anthropic"`. |
| `Config file not found` | Run from the project root (where `config/` and `data/` live) |
| PWA shows "Disconnected" | Cosmetic — chat works via POST regardless of SSE status |

### Quality checks

```bash
make lint          # ruff check
make format        # ruff format (writes changes)
make format-check  # ruff format --check (CI gate, no writes)
make typecheck     # mypy strict
make test          # pytest with coverage
```

## Recommended Models

All models below support native tool/function calling via Ollama.

| Model | Params | RAM (Q4) | Speed (M2) | Ollama Tag | Notes |
|-------|--------|----------|------------|------------|-------|
| **Gemma 4 12B** | 12B | ~8-10GB | 5-15s | `gemma4:12b` | **Recommended.** Best quality/speed balance for M2 24GB. |
| Gemma 4 E4B | 4.5B eff | ~3GB | 2-5s | `gemma4:e4b` | Lightweight. Good for quick tasks. |
| Gemma 4 27B | 27B | ~18GB | 15-40s | `gemma4:27b` | Highest quality. Tight fit on 24GB with Docker. |
| Gemma 4 E2B | 2.3B eff | ~2GB | 1-3s | `gemma4:e2b` | Minimal. For constrained hardware (8GB RAM). |
| Qwen 2.5 Coder 14B | 14B | ~10GB | 5-15s | `qwen2.5-coder:14b` | Alternative. Strong tool calling. |

## Architecture Decisions

This section documents key decisions about where we use proven third-party libraries versus custom code, and why. Contributors should read this before proposing changes to any of these areas.

### Guiding Principle

> Use well-proven libraries for infrastructure plumbing (HTTP, validation, web routing, encryption). Write our own code for security-critical logic (agent loop, permission engine, tool dispatch, audit logging). Never use a library that abstracts the agent's decision-making or introduces a third-party data channel.

### Where We Use Libraries (and Why)

| Library | Used For | Why Not Custom |
|---------|----------|----------------|
| **FastAPI** | HTTP routing, SSE, static files, OpenAPI | Industry-standard, native Pydantic integration, well-audited. No reason to hand-roll HTTP. |
| **uvicorn** | ASGI server | Production-grade, standard FastAPI pairing. |
| **Pydantic v2** | All data validation, config, models | Type-safe, Rust core, FastAPI-native. Validation is not our core domain. |
| **pydantic-settings** | Config loading with env var overrides | Official Pydantic companion. Handles YAML sources + env vars + secrets natively. Avoids custom env override logic. |
| **httpx** | Async HTTP client (Ollama, Google APIs) | Best async HTTP client for Python. We don't reinvent HTTP. |
| **pyyaml** | YAML config parsing | `yaml.safe_load()` is safe and standard. YAML is more readable than JSON for human-edited config. |
| **cryptography** | Fernet encryption for OAuth tokens | Well-audited, widely-used. We never implement our own crypto. |
| **asyncpg** | Async PostgreSQL driver (settings, permissions, memory) | Fastest async Postgres driver for Python. Native connection pooling and prepared statements. Required for non-blocking DB access in the async stack. |
| **google-api-python-client** | Gmail, Google Calendar, Google Drive API access | Official Google SDK. |
| **msal** | Microsoft OAuth2 (Outlook, Outlook Calendar, OneDrive) | Official Microsoft Authentication Library. Handles token acquisition and refresh for Microsoft Graph API. |

### Where We Write Custom Code (and Why)

#### 1. Audit Logger (`audit.py`) -- Custom NDJSON Writer

**Decision:** Custom implementation instead of Python's `logging` module or structlog/loguru.

**Why:**
- Python's `logging.FileHandler` does not support `O_NOFOLLOW`, `dir_fd`, or `0o600` file permissions -- these are security requirements to prevent symlink attacks and restrict file access to the owning user.
- No logging library enforces a write-only API surface (our spec requires the agent cannot read its own audit log).
- We need NDJSON (one validated Pydantic JSON object per line), not human-readable log messages. Using `logging` would mean writing a custom `Handler` + custom `Formatter` + custom opener -- the same amount of code, wrapped in an abstraction that buys us nothing.
- Path confinement (preventing traversal attacks via `resolve()` + `is_relative_to()` + `dir_fd`) is not a feature of any logging library.
- The implementation is small, focused, and well-tested.

**Alternatives evaluated:** Python `logging` module, `structlog`, `loguru`. All would require the same custom security code as subclasses/plugins, adding abstraction without reducing complexity.

#### 2. Credential Redaction (`models.py`) -- Custom Regex Patterns

**Decision:** Custom `_strip_credentials()` with 10 compiled regex patterns + NFKC Unicode normalization.

**Why:**
- No existing library covers our exact credential pattern set: Google OAuth access tokens (`ya29.`), Google refresh tokens (`1//`), JWTs, Bearer headers, GitHub PATs (`ghp_`/`ghs_`), AWS access keys (`AKIA`), Slack tokens (`xoxb-`/`xoxp-`), Google client secrets (`GOCSPX-`), and generic API keys (`sk-`).
- `scrubadub` targets PII (names, emails, SSNs) -- it would miss all of the above.
- `detect-secrets` and `trufflehog` are repo-scanning CLI tools, not per-field runtime sanitizers.
- The implementation is compact, with exhaustive parametrized tests across all patterns.

**Alternatives evaluated:** `scrubadub`, `detect-secrets`, `trufflehog`. None operate as real-time field validators.

#### 3. LLM Clients (`llm_ollama.py`, `llm_anthropic.py`, `llm_openai.py`) -- Mixed Strategy

**Decision:** Custom httpx client for Ollama, official SDKs (`anthropic`, `openai`) for the proprietary providers. A shared `llm.py` module defines the `LLMClient` protocol, a factory that imports only the provider selected in config, and shared sanitizers (control-char stripping, size limits, Pydantic tool-call validation).

**Why:**
- **Ollama:** its HTTP API is one endpoint (`POST /api/chat`). A ~20-line custom httpx client is simpler than pulling in `ollama-python`, and lets us own the sanitization layer directly around the network boundary.
- **Anthropic / OpenAI:** their APIs are much more involved (multipart content blocks, typed errors, streaming, retries, tool-use IDs). The official SDKs handle this correctly and are maintained by the vendors. We wrap them with the same sanitizers and tool-call validators used for Ollama, so the security-critical layer still runs at the trust boundary.
- **Isolation:** only the configured provider's module (and its SDK) is imported at startup. An admino deployment running on Ollama never loads `anthropic` or `openai`.
- **Interchangeability:** every provider module implements the same `LLMClient` protocol, so the agent loop is provider-agnostic.

**Alternatives evaluated:**
- `ollama-python` (official SDK) — rejected. Abstracting the single-endpoint call buys nothing and hides the sanitization layer.
- Hand-rolling Anthropic/OpenAI clients from httpx — rejected. The APIs are rich enough that re-implementing them would be an ongoing maintenance burden with no security benefit; the SDKs do not make decisions for us, they just format requests and parse responses.

#### 4. Permission Engine (`permissions.py`) -- Custom Pure Function

**Decision:** Custom `check_permission()` pure function instead of an RBAC/policy library.

**Why:**
- The permission model is a simple three-state lookup (allow/confirm/deny) with hardcoded denials that cannot be overridden by config.
- It must be a pure function with zero side effects (no logging, no I/O, no state mutation) and must never import from the agent, LLM, or server modules.
- No generic RBAC library (Casbin, OPA, etc.) would enforce our hardcoded security denials or write-mutation downgrade rules. We'd end up fighting the abstraction.
- The implementation is small. An RBAC library would be orders of magnitude more complex for a simpler result.

**Alternatives evaluated:** Casbin, django-guardian, OPA. All are designed for multi-user RBAC -- overkill and wrong abstraction for a single-user agent with static rules.

#### 5. Agent Loop (`agent.py`) -- Custom (Required by Spec)

**Decision:** Custom agent loop instead of LangChain, LangGraph, CrewAI, AutoGen, or LlamaIndex.

**Why:**
- The spec explicitly bans all agent framework libraries. The agent loop, tool dispatch, and LLM interaction must be explicit and auditable -- this is our core logic.
- These frameworks abstract decision-making, introduce third-party data channels, and make security auditing impractical.
- Our agent loop is a constrained-action executor (the LLM decides HOW to use pre-defined tools, not WHAT tools exist). This is fundamentally simpler than what agent frameworks are designed for.

### Banned Dependencies

| Package | Reason |
|---------|--------|
| LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex | Abstract the agent loop. Our agent logic must be explicit and auditable. |
| Flask, Django | Wrong framework. FastAPI is the approved web framework. |
| python-telegram-bot, signalbot, slack-sdk | Third-party messaging platforms. All data would route through their servers. |

## Project Structure

```
admino/
  docker-compose.yml         -- base: agent only (provider-agnostic)
  docker-compose.ollama.yml  -- overlay: adds `local-llm` via Ollama
  docker-compose.vllm.yml    -- overlay: adds `local-llm` via vLLM (GPU)
  Dockerfile
  Makefile                   -- docker-{build,up,down,logs} accept BACKEND={ollama,vllm}
  entrypoint.sh              -- iptables egress whitelist + start server
  src/admino/
    main.py            -- entry point, load config, start uvicorn
    server.py          -- FastAPI app, routes, SSE, static files
    agent.py           -- agent loop, LLM interaction, tool dispatch
    llm.py             -- LLM client protocol + provider factory + shared sanitizers
    llm_ollama.py      -- Ollama backend (default): httpx client for /api/chat
    llm_anthropic.py   -- Anthropic Claude backend (opt-in): anthropic SDK
    llm_openai.py      -- OpenAI backend (opt-in): openai SDK
    permissions.py     -- permission engine (pure function, isolated)
    audit.py           -- append-only NDJSON logger
    config.py          -- Pydantic config models for YAML + env vars
    models.py          -- shared Pydantic models
    oauth.py           -- OAuth token management, Fernet encryption
    oauth_setup.py     -- CLI for one-time OAuth consent
    database.py        -- PostgreSQL connection pool, migration runner, seed logic (asyncpg)
    migrations/        -- SQL schema migrations
    tools/
      registry.py        -- tool registration + dispatch
      gmail.py           -- Gmail read/list/search (Google API)
      google_calendar.py -- Google Calendar read/list/create (Google API)
      google_drive.py    -- Google Drive read/list/search/download (Google API)
      outlook.py         -- Outlook mail read/list/search (Microsoft Graph)
      outlook_calendar.py -- Outlook Calendar read/list/create (Microsoft Graph)
      onedrive.py        -- OneDrive read/list/search/download (Microsoft Graph)
      files.py           -- Local file read/list/search/write/move
      memory.py          -- Persistent key-value notes (PostgreSQL)
```

## Deviations from Specification

The following intentional deviations from the original product specification improve security or reflect practical v1 choices:

| Area | Spec Says | Implementation | Rationale |
|------|-----------|---------------|-----------|
| Ollama image tag | `ollama/ollama:latest` | `ollama/ollama:0.6.2` (pinned) | Supply chain security — prevents silent image changes. |
| Port binding | `8000:8000` | `127.0.0.1:8000:8000` | Localhost-only by default — prevents unintended LAN exposure. |
| API flow | Async (202 Accepted + SSE stream) | Synchronous (200 OK + ChatResponse) | Simpler v1. SSE streaming infrastructure exists but is not wired end-to-end yet. |
| SSE event names | `thinking`, `confirmation_required`, `confirmation_resolved`, `tool_result` | `status`, `confirm`, `tool_call`, `message`, `done` | Functionally equivalent; the PWA uses these names. Will align naming in v2 if needed. |
| Session ID generation | Server-generated UUID | Client-generated (timestamp + random hex) | Acceptable for single-user, local-only deployment. |
| Default model | `qwen2.5-coder:14b` | `gemma4:12b` | Gemma 4 (April 2026) has native tool calling, better quality at similar size. |
| Docker Compose Ollama | Always starts | Provider-agnostic `local-llm` service in `docker-compose.ollama.yml` overlay (opt-in via `make docker-up BACKEND=ollama`) | Laptop mode uses native Ollama for Metal GPU acceleration; the overlay pattern also accommodates vLLM and future backends without touching the base file. |
| Health endpoint | Returns `model`, `ollama_reachable`, `uptime_s` | Returns `{"status": "ok"}` only | Enriched response planned for v1 completion. |

## Outstanding for Complete v1

### Blocking (must implement before full v1 release)

| # | Item | Files Needed | Priority |
|---|------|-------------|----------|
| 1 | **Tool modules: Documents** — store (LLM-based extraction/classification), search, query. Will define its own schema migration when built | `tools/documents.py` | P1 |
| 2 | **Tool modules: Web Search** — via SearXNG or Brave Search API | `tools/search.py` | P2 |

### Non-Blocking (required for v1 but not for basic operation)

| # | Item | Details | Priority |
|---|------|---------|----------|
| 3 | **Tests for outstanding tools** | `test_documents.py`, `test_search.py` (once those tools land) | P1 |
| 4 | **Health endpoint enrichment** | Add `model`, `ollama_reachable`, `uptime_s` to GET /health response | P2 |
| 5 | **`DEPENDENCIES.md`** | Document every direct dependency with name, version, purpose, justification (§9.7) | P2 |
| 6 | **`conftest.py` shared fixtures** | Mock Ollama, test config, test DB fixtures for test organization | P3 |
| 7 | **Adversarial/security tests** | `tests/test_security.py` — prompt injection, SQL injection, path traversal, control chars (§12.2) | P1 |
| 8 | **Integration tests** | Full request flow: POST message -> tool execution -> response; confirmation flow end-to-end | P1 |

### Currently Implemented

- **Core infrastructure**: server.py, agent.py, llm.py, permissions.py, audit.py, config.py, models.py, main.py
- **Database**: database.py (asyncpg connection pool, migration runner, seed logic), migrations/ (PostgreSQL schema)
- **OAuth**: oauth.py (Fernet encryption, token refresh — Google + Microsoft/MSAL), oauth_setup.py (CLI consent flow)
- **Tool registry**: tools/registry.py (registration, dispatch, permission enforcement)
- **Tool modules**: tools/memory.py (PostgreSQL key-value store), tools/files.py (path-validated file access), and the OAuth-backed tools/gmail.py, tools/google_calendar.py, tools/google_drive.py, tools/outlook.py, tools/outlook_calendar.py, tools/onedrive.py
- **PWA**: Vue 3 + Vite app in `static-src/`, built to `static/` (`index.html`, hashed JS/CSS bundles under `assets/`, `manifest.webmanifest`, `service-worker.js`, fonts, icons)
- **DevOps**: Dockerfile, docker-compose.yml (base), docker-compose.ollama.yml + docker-compose.vllm.yml (provider overlays), entrypoint.sh (iptables egress whitelist), Makefile (BACKEND variable for overlay selection), .env.example, .gitignore, .dockerignore
- **Tests**: backend pytest suite with coverage reporting (coverage gate enforced in CI)
- **Security**: CSP headers, egress whitelist, credential sanitization, TOCTOU-safe file writes, path confinement

## License

Private. All rights reserved.
