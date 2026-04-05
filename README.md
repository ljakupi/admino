# admino

Local-only, security-first personal AI agent. Python 3.12+, FastAPI, Pydantic v2, Ollama for LLM inference, Docker Compose deployment.

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev]"

# Run quality checks
make lint        # ruff check
make format      # ruff format
make typecheck   # mypy strict
make test        # pytest with coverage

# Run locally (dev mode)
make run

# Docker
make docker-build
make docker-up
```

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

## License

Private. All rights reserved.
