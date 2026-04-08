# admino

Local-only, security-first personal AI agent. Python 3.12+, FastAPI, Pydantic v2, Ollama for LLM inference, Docker Compose deployment.

## How to Run

### Option A: Local dev mode (MacBook, recommended)

This runs the Python app directly on your machine with native Ollama for Metal GPU acceleration. Fastest setup.

```bash
# 1. Install Ollama (if not already installed)
#    Download from https://ollama.ai or:
brew install ollama

# 2. Start Ollama and pull the model (~8-10 GB download, one-time)
ollama serve &                   # start Ollama in background (skip if already running)
ollama pull gemma4:12b           # download the model

# 3. Clone and install Python dependencies
git clone <repo-url> admino && cd admino
pip install -e ".[dev]"

# 4. Set up environment
cp .env.example .env
# Edit .env if needed — defaults work for local dev with VPN auth mode

# 5. Update config for local dev (native Ollama on localhost)
#    Edit config/config.yaml and set:
#      ollama.url: "http://localhost:11434"
#    (The default is host.docker.internal which is for Docker mode)

# 6. Create data directories
mkdir -p data/db data/logs data/images data/tokens

# 7. Start the agent
make run
```

Open **http://localhost:8000** in your browser. You should see the admino PWA. Type a message and hit Enter.

### Option B: Docker (agent container + native Ollama)

Runs the agent in Docker but uses your native Ollama installation for GPU acceleration.

```bash
# 1. Make sure Ollama is running natively with the model pulled
ollama serve &
ollama pull gemma4:12b

# 2. Set up environment
cp .env.example .env

# 3. Create data directories (mounted as Docker volumes)
mkdir -p data/db data/logs data/images data/tokens

# 4. Build and start
make docker-build
make docker-up
```

Open **http://localhost:8000**.

### Option C: Full Docker (agent + Ollama in containers, for VPS)

Runs everything in Docker. No native Ollama needed. Slower on Mac (no Metal GPU).

```bash
# 1. Set up environment
cp .env.example .env
# Edit .env: set OLLAMA_BASE_URL=http://ollama:11434

# 2. Edit config/config.yaml: set ollama.url to "http://ollama:11434"

# 3. Create data directories
mkdir -p data/db data/logs data/images data/tokens

# 4. Build and start both containers
docker compose --profile with-ollama up -d

# 5. Pull the model into the Ollama container (one-time, ~8-10 GB)
docker compose exec ollama ollama pull gemma4:12b
```

Open **http://localhost:8000**.

### What to expect

Once running, the PWA will:

1. Prompt for a Bearer token on first visit (click **Skip** for VPN mode / local dev)
2. Show a chat interface — type any message and press Enter
3. The agent sends your message to Ollama, which may respond with tool calls
4. Currently implemented tools: `memory.store/recall/list` and `files.read/list/search/write/move`
5. Other tools (gmail, calendar, news, etc.) are not yet implemented — the agent will handle those gracefully with a text-only response

### Troubleshooting

| Problem | Fix |
|---------|-----|
| "Connection refused" on port 8000 | Make sure the agent is running: `make run` or `docker compose ps` |
| "Connection refused" to Ollama | Make sure Ollama is running: `ollama serve` or check `ollama list` |
| Slow first response | First inference loads the model into memory. Subsequent responses are faster. |
| "Model not found" | Run `ollama pull gemma4:12b` (or whichever model is in your config) |
| PWA shows "Disconnected" | The SSE connection status dot is cosmetic — the chat works via POST requests regardless |

### Quality checks

```bash
make lint        # ruff check
make format      # ruff format
make typecheck   # mypy strict
make test        # pytest with coverage (954 tests, 94% coverage)
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
| **aiosqlite** | Async SQLite (memory tool, documents) | Thin async wrapper around sqlite3. Required for non-blocking DB access in the async stack. |
| **google-api-python-client** | Gmail, Calendar API access | Official Google SDK. |
| **Pillow** | Image processing for document OCR | Standard image library. |
| **beautifulsoup4 + lxml** | HTML parsing (news, web scraping) | Proven parsers, no reason to hand-roll HTML parsing. |

### Where We Write Custom Code (and Why)

#### 1. Audit Logger (`audit.py`) -- Custom NDJSON Writer

**Decision:** Custom implementation instead of Python's `logging` module or structlog/loguru.

**Why:**
- Python's `logging.FileHandler` does not support `O_NOFOLLOW`, `dir_fd`, or `0o600` file permissions -- these are security requirements to prevent symlink attacks and restrict file access to the owning user.
- No logging library enforces a write-only API surface (our spec requires the agent cannot read its own audit log).
- We need NDJSON (one validated Pydantic JSON object per line), not human-readable log messages. Using `logging` would mean writing a custom `Handler` + custom `Formatter` + custom opener -- the same amount of code, wrapped in an abstraction that buys us nothing.
- Path confinement (preventing traversal attacks via `resolve()` + `is_relative_to()` + `dir_fd`) is not a feature of any logging library.
- The implementation is ~65 statements with 100% test coverage. It is small, focused, and well-tested.

**Alternatives evaluated:** Python `logging` module, `structlog`, `loguru`. All would require the same custom security code as subclasses/plugins, adding abstraction without reducing complexity.

#### 2. Credential Redaction (`models.py`) -- Custom Regex Patterns

**Decision:** Custom `_strip_credentials()` with 10 compiled regex patterns + NFKC Unicode normalization.

**Why:**
- No existing library covers our exact credential pattern set: Google OAuth access tokens (`ya29.`), Google refresh tokens (`1//`), JWTs, Bearer headers, GitHub PATs (`ghp_`/`ghs_`), AWS access keys (`AKIA`), Slack tokens (`xoxb-`/`xoxp-`), Google client secrets (`GOCSPX-`), and generic API keys (`sk-`).
- `scrubadub` targets PII (names, emails, SSNs) -- it would miss all of the above.
- `detect-secrets` and `trufflehog` are repo-scanning CLI tools, not per-field runtime sanitizers.
- The implementation is ~40 lines with exhaustive parametrized tests across all patterns.

**Alternatives evaluated:** `scrubadub`, `detect-secrets`, `trufflehog`. None operate as real-time field validators.

#### 3. Ollama LLM Client (`llm.py`) -- Custom httpx Client

**Decision:** Custom async client instead of the official `ollama-python` SDK.

**Why:**
- The Ollama HTTP API is trivial (one endpoint: `POST /api/chat`). The HTTP call is ~20 lines.
- The value of our code is in what happens around the call: response sanitization (control character removal), size limits (per-chunk and cumulative), tool call validation against Pydantic schemas, and graceful degradation on malformed responses.
- The `ollama-python` SDK would abstract away our sanitization layer, which is security-critical.
- The spec explicitly bans libraries that "abstract the agent's decision-making" -- LLM interaction is part of that.

**Alternatives evaluated:** `ollama-python` (official SDK). Rejected because it would hide our security-critical sanitization and validation logic behind an abstraction.

#### 4. Permission Engine (`permissions.py`) -- Custom Pure Function

**Decision:** Custom `check_permission()` pure function instead of an RBAC/policy library.

**Why:**
- The permission model is a simple three-state lookup (allow/confirm/deny) with hardcoded denials that cannot be overridden by config.
- It must be a pure function with zero side effects (no logging, no I/O, no state mutation) and must never import from the agent, LLM, or server modules.
- No generic RBAC library (Casbin, OPA, etc.) would enforce our hardcoded security denials or write-mutation downgrade rules. We'd end up fighting the abstraction.
- The implementation is ~44 statements. An RBAC library would be orders of magnitude more complex for a simpler result.

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
| pytesseract | Our OCR call is 3 lines of `subprocess.run` -- a dependency is not justified. |

## Project Structure

```
src/admino/
  main.py         -- entry point, load config, start uvicorn
  server.py       -- FastAPI app, routes, SSE, static files
  agent.py        -- agent loop, LLM interaction, tool dispatch
  llm.py          -- Ollama client via httpx
  permissions.py  -- permission engine (pure function, isolated)
  audit.py        -- append-only NDJSON logger
  config.py       -- Pydantic config models for YAML + env vars
  models.py       -- shared Pydantic models
  oauth.py        -- OAuth token management, Fernet encryption
  oauth_setup.py  -- CLI for one-time OAuth consent
  tools/
    registry.py   -- tool registration + dispatch
    gmail.py      -- Gmail read/list/search
    calendar.py   -- Calendar read/list/create
    news.py       -- News fetch
    documents.py  -- Document store/classify/search/query + OCR
    search.py     -- Web search
    files.py      -- Local file read/list/search/write/move
    memory.py     -- Persistent key-value notes (SQLite)
    aggregate.py  -- Cross-source search + dedup
    recipes.py    -- YAML recipe loader + executor
```

## Deviations from Specification

The following intentional deviations from `final_requirements.md` improve security or reflect practical v1 choices:

| Area | Spec Says | Implementation | Rationale |
|------|-----------|---------------|-----------|
| Ollama image tag | `ollama/ollama:latest` | `ollama/ollama:0.6.2` (pinned) | Supply chain security — prevents silent image changes. |
| Port binding | `8000:8000` | `127.0.0.1:8000:8000` | Localhost-only by default — prevents unintended LAN exposure. |
| API flow | Async (202 Accepted + SSE stream) | Synchronous (200 OK + ChatResponse) | Simpler v1. SSE streaming infrastructure exists but is not wired end-to-end yet. |
| SSE event names | `thinking`, `confirmation_required`, `confirmation_resolved`, `tool_result` | `status`, `confirm`, `tool_call`, `message`, `done` | Functionally equivalent; the PWA uses these names. Will align naming in v2 if needed. |
| Session ID generation | Server-generated UUID | Client-generated (timestamp + random hex) | Acceptable for single-user, local-only deployment. |
| Default model | `qwen2.5-coder:14b` | `gemma4:12b` | Gemma 4 (April 2026) has native tool calling, better quality at similar size. |
| Docker Compose Ollama | Always starts | Behind `with-ollama` profile | Laptop mode uses native Ollama for Metal GPU acceleration. |
| Health endpoint | Returns `model`, `ollama_reachable`, `uptime_s` | Returns `{"status": "ok"}` only | Enriched response planned for v1 completion. |

## Outstanding for Complete v1

### Blocking (must implement before full v1 release)

| # | Item | Files Needed | Priority |
|---|------|-------------|----------|
| 1 | **Tool modules: Gmail** — read, list, search via Google API | `tools/gmail.py` | P0 |
| 2 | **Tool modules: Calendar** — read, list, create (with confirmation) via Google API | `tools/calendar.py` | P0 |
| 3 | **Tool modules: News** — fetch via RSS or privacy-respecting API | `tools/news.py` | P1 |
| 4 | **Tool modules: Documents** — store (OCR + LLM classification), search, query. SQLite schema from spec §3.4 | `tools/documents.py` | P1 |
| 5 | **Tool modules: Web Search** — via SearXNG or Brave Search API | `tools/search.py` | P2 |
| 6 | **Tool modules: Aggregate** — cross-source search + deduplication | `tools/aggregate.py` | P1 |
| 7 | **Tool modules: Recipes** — YAML loader, date resolver, step runner | `tools/recipes.py` | P1 |
| 8 | **Tool argument Pydantic models** — Gmail, Calendar, News, Documents, WebSearch, Aggregate, Recipe arg schemas | `models.py` additions | P0 |
| 9 | **SQLite schema initialization** — `CREATE TABLE documents(...)` and migration logic | `tools/documents.py` | P1 |

### Non-Blocking (required for v1 but not for basic operation)

| # | Item | Details | Priority |
|---|------|---------|----------|
| 10 | **Tool-specific tests** | `tests/test_tools/test_gmail.py`, `test_calendar.py`, `test_documents.py`, `test_files.py`, `test_memory.py`, `test_aggregate.py`, `test_recipes.py` | P1 |
| 11 | **Health endpoint enrichment** | Add `model`, `ollama_reachable`, `uptime_s` to GET /health response | P2 |
| 12 | **`DEPENDENCIES.md`** | Document every direct dependency with name, version, purpose, justification (§9.7) | P2 |
| 13 | **`conftest.py` shared fixtures** | Mock Ollama, test config, test DB fixtures for test organization | P3 |
| 14 | **Adversarial/security tests** | `tests/test_security.py` — prompt injection, SQL injection, path traversal, control chars (§12.2) | P1 |
| 15 | **Integration tests** | Full request flow: POST message -> tool execution -> response; confirmation flow end-to-end | P1 |

### Currently Implemented

- **Core infrastructure**: server.py, agent.py, llm.py, permissions.py, audit.py, config.py, models.py, main.py
- **OAuth**: oauth.py (Fernet encryption, token refresh), oauth_setup.py (CLI consent flow)
- **Tool registry**: tools/registry.py (registration, dispatch, permission enforcement)
- **Tool modules**: tools/memory.py (SQLite key-value store), tools/files.py (path-validated file access)
- **PWA**: index.html, style.css, app.js, service-worker.js, manifest.json, icons
- **DevOps**: Dockerfile, docker-compose.yml, entrypoint.sh, Makefile, .env.example, .gitignore, .dockerignore
- **Tests**: 954 tests, 94% coverage on core modules (all core modules above 80%)
- **Security**: CSP headers, egress whitelist, credential sanitization, TOCTOU-safe file writes, path confinement

## License

Private. All rights reserved.
