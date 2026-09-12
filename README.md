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
- 🤖 **Your choice of model** — local-first vLLM on Apple Silicon (Metal, available now), with Claude and OpenAI as opt-in cloud providers. → [Configuration](docs/configuration.md)

## 📸 Screenshots

| Chat | An action pausing for your approval |
| :---: | :---: |
| ![Chat](docs/screenshots/chat.png) | ![Approval prompt](docs/screenshots/confirm-chat.png) |

<p align="center"><sub>A <code>confirm</code> action — <code>google_calendar.create</code> — waiting for approval before it runs.</sub></p>

## 🚀 Quick start

### Requirements

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** — the package & virtualenv manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Docker** + Docker Compose — runs PostgreSQL (and, optionally, the whole backend)
- **For local inference (Apple Silicon, macOS 15+):** run `make vllm-pull && make vllm-up` to download the default model (~6.7 GB) and start the host server — then `make docker-up` and you're chatting with no cloud calls. See [Configuration → Local vLLM](docs/configuration.md#local-vllm-apple-silicon).
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
the vLLM server (see below), you're ready to chat. Otherwise open **Settings → Agent**
and switch to **Claude** or **OpenAI** (set the matching API key in `.env` first).

### Local vLLM serving — Apple Silicon (macOS 15+, Metal)

admino's local-first default is **Gemma 4 12B instruction-tuned, MLX 4-bit**
(`mlx-community/gemma-4-12B-it-4bit`, ~6.7 GB). It runs as a host-native process via
[vllm-metal](https://github.com/vllm-project/vllm-metal) (Docker cannot pass through
the Metal GPU). Install vllm-metal once, then:

```bash
make vllm-pull   # one-time download (~6.7 GB) — set HF_TOKEN if using a gated model
make vllm-up     # start the server on :8000 in the background
# Model takes 1-2 minutes to finish loading — tail -f data/logs/vllm-metal.log
make vllm-down   # stop the server when done
```

The agent container reaches the server at `host.docker.internal:8000` (configured in
`config.yaml`). Until the server is up, admino boots and replies with a friendly
"model unavailable" message rather than crashing.

**Alternative — Docker Model Runner** (Docker Desktop 4.62+):
`docker model install-runner --backend vllm && docker model pull mlx-community/gemma-4-12B-it-4bit`
then set `VLLM_BASE_URL=http://model-runner.docker.internal/engines/v1` in `.env`.

Linux + NVIDIA in-container serving is tracked in **[#132](https://github.com/ljakupi/admino/issues/132)**.

### Run the whole backend in Docker

Starts the agent (behind its egress firewall) and PostgreSQL together — Docker reads
`.env` directly, so no shell export needed:

```bash
cp .env.example .env               # change PG_PASSWORD; set API key if using cloud
make vllm-pull && make vllm-up     # Apple Silicon only — skip if using a cloud provider
make docker-build
make docker-up                     # → http://localhost:8000
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

- **Local vLLM serving — Linux/NVIDIA** (in-container) — tracked in [#132](https://github.com/ljakupi/admino/issues/132). Apple Silicon (Metal) is available now.
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
