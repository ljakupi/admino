# admino — Project Instructions

## What This Is
admino is a security-first personal AI agent. Python 3.12+, FastAPI + uvicorn, Pydantic v2. LLM inference via Ollama (default, local) or proprietary APIs (Anthropic Claude, OpenAI — opt-in). Docker Compose deployment. Laptop-first (Mac/Linux), VPS optional. See `final_requirements.md` for the full specification.

@final_requirements.md

## Architecture Summary
- **Agent container:** FastAPI app (uvicorn) serving HTTP on port 8000. REST + SSE API. Static PWA files.
- **LLM providers:** Ollama (default, local), Anthropic Claude (opt-in), OpenAI (opt-in). Provider selected via `llm.provider` in config.yaml.
- **Ollama:** Native on laptop (Metal GPU) or Docker container on VPS. Internal network. Zero external access (Docker mode).
- **Permission engine:** Pure function. Receives (tool, action) tuple only. Never sees LLM context.
- **Audit log:** Append-only NDJSON. Two log types: conversation + tool_call. Designed for fine-tuning data extraction.

## Build & Run Commands
- `make lint` — ruff check
- `make format` — ruff format
- `make typecheck` — mypy/pyright strict
- `make test` — pytest with coverage
- `make docker-build` — build containers
- `make docker-up` — start via docker compose
- `make run` — run agent locally (dev mode)

## Code Standards (Non-Negotiable)
- Python 3.12+. Full type annotations on ALL signatures and attributes.
- Pydantic v2 for all validation (config, tool args, API types).
- FastAPI for web routing, request handling, SSE, static files.
- ruff with strict config: `select = ["E", "F", "W", "I", "N", "UP", "S", "B", "A", "C4", "SIM", "TCH", "RUF"]`.
- All modules have docstrings (purpose, inputs, outputs, security notes).
- Keep modules small, focused, single-responsibility. No dead code, no unnecessary abstractions.
- Parameterized SQL only. No string interpolation in queries. No raw SQL from LLM.
- `subprocess.run` with `shell=False` only, hardcoded argv, Tesseract only.
- No `eval`, `exec`, `compile`, `importlib`, `shell=True`.
- No LangChain, LangGraph, CrewAI, AutoGen, Flask, Django, or any banned dependency (see final_requirements.md Section 9.6).

## Security Rules (Read These Before Every Change)
- No plaintext secrets on filesystem. Encrypted at rest or env vars only.
- No credentials in log output. Sanitize args before logging.
- Permission engine must never import from agent.py, llm*.py, or server.py.
- Ollama container (VPS mode): zero external network access.
- Agent container: whitelist-only egress.
- Hardcoded denials (gmail.send, gmail.delete, google_calendar.delete, google_calendar.update, google_drive.delete, outlook.send, outlook.delete, outlook_calendar.delete, outlook_calendar.update, onedrive.delete, documents.delete, files.delete, files.overwrite, memory.delete) cannot be overridden by YAML config.

## Module Layout
src/admino/
  main.py         — entry point, load config, start uvicorn
  server.py       — FastAPI app, routes, SSE, static files
  agent.py        — agent loop, LLM interaction, tool dispatch
  llm.py          — LLM client protocol (interface) + provider factory
  llm_ollama.py   — Ollama backend (default): httpx client
  llm_anthropic.py — Anthropic Claude backend (opt-in)
  llm_openai.py   — OpenAI backend (opt-in)
  permissions.py  — permission engine (pure function, isolated)
  audit.py        — append-only NDJSON logger (conversation + tool_call entries)
  config.py       — Pydantic models for config.yaml + permissions.yaml
  models.py       — shared Pydantic models (tool args, API types, audit entry)
  oauth.py        — OAuth token management, Fernet encryption
  oauth_setup.py  — CLI for one-time OAuth consent
  tools/
    registry.py        — tool registration + dispatch
    gmail.py           — Gmail read/list/search (Google API)
    google_calendar.py — Google Calendar read/list/create (Google API)
    google_drive.py    — Google Drive read/list/search/download (Google API)
    outlook.py         — Outlook mail read/list/search (Microsoft Graph)
    outlook_calendar.py — Outlook Calendar read/list/create (Microsoft Graph)
    onedrive.py        — OneDrive read/list/search/download (Microsoft Graph)
    documents.py       — Document store/classify/search/query + OCR
    search.py          — Web search
    files.py           — Local file read/list/search/write/move (path-validated)
    memory.py          — Persistent key-value notes (SQLite)

## Available Agents
- `backend-dev` — Core Python modules. Use for implementing any src/ code.
- `test-writer` — pytest suite. Use after a module is implemented.
- `security-reviewer` — Read-only security audit. Use after code is written to check for vulnerabilities.
- `devops` — Docker, Makefile, CI, deployment configs.
- `frontend-dev` — PWA static files (index.html, service-worker.js, manifest.json).
