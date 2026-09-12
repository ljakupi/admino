<p align="center">
  <img src="static-src/public/admino_avatar.png" alt="admino" width="120" height="120">
</p>

<p align="center">
  <img src="static-src/public/admino_logo.svg" alt="admino" height="56">
</p>

<p align="center">
  <b>The AI that works for you, not on you.</b><br>
  <sub>A privacy- and security-first personal AI agent you run yourself.</sub>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-0B5D45.svg"></a>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-0B5D45.svg?logo=python&logoColor=white">
  <img alt="Status" src="https://img.shields.io/badge/status-v0.1_alpha-e08e0b.svg">
  <a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

<p align="center">
  <a href="docs/getting-started.md">Getting&nbsp;Started</a> ·
  <a href="docs/permissions.md">Permissions</a> ·
  <a href="docs/SECURITY.md">Security&nbsp;Model</a> ·
  <a href="docs/tools.md">Tools</a> ·
  <a href="docs/configuration.md">Configuration</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

admino chats with you and can act on your behalf — reading your mail, calendar, and
files — but **every action it takes is gated by an isolated permission engine the model
can neither see nor bypass**. Read actions run freely; anything that changes state pauses
for your approval; a handful of destructive actions are denied outright. You run it on
your own machine, your data stays with you, and nothing happens on your accounts without
your say-so.

## ✨ Why admino

- 🔐 **Isolated permission engine** — a pure `(tool, action)` function the LLM never sees, can't argue with, and can't route around. Default-deny; writes are never silently auto-allowed. → [Permissions](docs/permissions.md)
- 🏠 **Runs on your machine** — local-first by design. Your audit log, memory, and documents never leave your computer.
- 🧯 **Contained blast radius** — the agent container is whitelist-only egress, so even a hijacked agent can't phone home. → [Security Model](docs/SECURITY.md)
- 🔑 **You own your data** — PostgreSQL on your box, OAuth tokens encrypted at rest, and an append-only audit log of every decision.
- 🧩 **Real tools** — Gmail, Google Calendar, Drive, Outlook, OneDrive, local files, and memory — all permission-gated. → [Tools](docs/tools.md)
- 🤖 **Your choice of model** — local-first vLLM as a cross-platform CPU container (Apple Silicon + Linux, no Metal, no host process), with Claude and OpenAI as opt-in cloud providers. → [Configuration](docs/configuration.md)

## 📸 Screenshots

| Chat | An action pausing for your approval |
| :---: | :---: |
| ![Chat](docs/screenshots/chat.png) | ![Approval prompt](docs/screenshots/confirm-chat.png) |

<p align="center"><sub>A <code>confirm</code> action — <code>google_calendar.create</code> — waiting for approval before it runs.</sub></p>

## 🚀 Quick start

### Requirements

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** — the package & virtualenv manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Docker** + Docker Compose — runs PostgreSQL and the vLLM container (and the whole backend, optionally)
- **For local inference (any platform):** run `make vllm-pull` to download the default model (~8 GB, one-time) then `make start` — admino spins up postgres, agent, and the vLLM CPU container together, with no cloud calls. See [Configuration → Local vLLM](docs/configuration.md#local-vllm-cpu-container). Docker Desktop needs ~12–16 GB RAM allocated.
- **For cloud providers:** an [Anthropic](https://console.anthropic.com/) or [OpenAI](https://platform.openai.com/api-keys) API key. Set it in `.env`, switch the provider in Settings → Agent, and start the backend — no local model required.
- *Optional:* Google / Microsoft OAuth apps to enable the mail, calendar, and drive tools — see [Getting Started → Connect your accounts](docs/getting-started.md#connect-your-accounts).

### Run locally (with uv)

```bash
# 1. Install dependencies — uv builds an isolated .venv from pyproject + uv.lock
uv sync --extra dev          # all providers + dev tooling
source .venv/bin/activate

# 2. Configure — copy the sample env
cp .env.example .env
#    PG_PASSWORD is prefilled with the dev default: changeme

# 3. Load .env into your shell — `make run` reads the shell environment, not .env
set -a; source .env; set +a

# 4. Start PostgreSQL (Docker), then the agent
make dev-db
make run
```

Open **http://localhost:8000** and click **Skip** on the token prompt. If you started
the vLLM container (see below), you're ready to chat once it loads. Otherwise open
**Settings → Agent** and switch to **Claude** or **OpenAI** (set the matching API key
in `.env` first).

### Local vLLM serving — CPU container (cross-platform)

admino's local-first default is **Qwen3 4B Instruct** (`Qwen/Qwen3-4B-Instruct-2507`).
It runs as a Docker CPU container — cross-platform on Apple Silicon and Linux, nothing
outside Docker, no Metal, no host process.

```bash
make vllm-pull   # one-time download (~8 GB) into a Docker volume — set HF_TOKEN if using a gated model
make start       # brings up postgres + agent + vllm together
make vllm-down   # stop just the vllm container when done
```

The agent reaches the vllm container at `http://vllm:8000/v1` over the shared internal
Docker bridge. Until the container is ready, admino boots and replies with a friendly
"model unavailable" message rather than crashing.

**Trade-offs:** CPU inference is slow (a few tokens/sec); a smaller model like
`Qwen/Qwen3-1.7B-Instruct-2507` is snappier. Docker Desktop needs **~12–16 GB RAM**
allocated (Settings → Resources → Memory) — the default 8 GB is not enough for a 4B
FP16 model. FP16 only (no 4-bit quant in the CPU image).

NVIDIA GPU serving is tracked in **[#132](https://github.com/ljakupi/admino/issues/132)**
(swap the CPU image for the CUDA image + add a GPU reservation).

### Run the whole backend in Docker

Starts the agent (behind its egress firewall) and PostgreSQL together — Docker reads
`.env` directly, so no shell export needed:

```bash
cp .env.example .env               # change PG_PASSWORD; set API key if using cloud
make vllm-pull                     # one-time model download — skip if using a cloud provider
make docker-build
make docker-up                     # → http://localhost:8000 (includes vllm container)
```

> **New here?** The [Getting Started guide](docs/getting-started.md) walks through
> configuration, connecting Google/Microsoft accounts, and your first chat in detail.

## 📚 Documentation

| Guide | What's inside |
| --- | --- |
| **[Getting Started](docs/getting-started.md)** | Install, configure, run (local & Docker), connect accounts, first chat |
| **[Permissions](docs/permissions.md)** | The permission engine: allow / confirm / deny, hardcoded denials, promotion flow |
| **[Tools](docs/tools.md)** | Every tool and action admino ships with today |
| **[Configuration](docs/configuration.md)** | LLM providers, `config.yaml`, data & storage, auth modes |
| **[Security Model](docs/SECURITY.md)** | Egress containment, the root→non-root privilege drop, threat model |

## 🗺️ Roadmap

- **Local vLLM serving — NVIDIA GPU** (in-container CUDA) — tracked in [#132](https://github.com/ljakupi/admino/issues/132). CPU inference (cross-platform) is available now.
- **Documents** store and **web search** tools.
- End-to-end SSE streaming and a richer health endpoint.

_Planned and **not** in this alpha — don't expect them to work yet._

## 🤝 Contributing

admino is **issue-driven** and **test-first**: every PR maps to an approved issue and must
pass the full quality gate (`make check`, ≥ 90 % coverage). Start with
[CONTRIBUTING.md](CONTRIBUTING.md).

Found a security issue? Please **don't** open a public issue — report it privately, as
described in the [Security Model](docs/SECURITY.md#reporting-a-vulnerability).

## 📄 License

Licensed under the [Apache License 2.0](LICENSE). Contributions are covered by the
[Contributor License Agreement](CLA.md).

<p align="center"><sub>Built with FastAPI · Pydantic · PostgreSQL · Vue 3 — and no agent frameworks.</sub></p>
