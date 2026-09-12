# Configuration

admino is configured by two things:

- **`config/config.yaml`** — non-secret application settings, validated by Pydantic at
  startup. The agent refuses to start on invalid config with a clear error.
- **Environment variables** — **all secrets** (API keys, OAuth client secrets, the
  encryption key, the auth token) and a few runtime overrides. Documented inline in
  [`.env.example`](../.env.example).

> **Secrets are never read from `config.yaml`.** They come from the environment only, and
> are never written to disk in plaintext.

- [LLM providers](#llm-providers)
- [Local vLLM (Apple Silicon)](#local-vllm-apple-silicon)
- [`config.yaml` reference](#configyaml-reference)
- [Authentication modes](#authentication-modes)
- [Data & storage](#data--storage)
- [Egress whitelist](#egress-whitelist)

## LLM providers

admino is local-first. **vLLM is the default provider**, served on Apple Silicon (macOS
15+, Metal) by a host-native process — no cloud calls by default.

| Provider | Status | Needs |
| --- | --- | --- |
| **vLLM** | **local · available (Apple Silicon)** (default) | Install `vllm-metal`, then `make vllm-pull` + `make vllm-up`. See below. |
| **Claude (Anthropic)** | opt-in cloud | `ANTHROPIC_API_KEY` in the environment. |
| **OpenAI** | opt-in cloud | `OPENAI_API_KEY` in the environment. |

Cloud providers send your messages to their servers; everything else — audit log, memory,
documents — stays on your machine. Until the vLLM server is running, admino boots and
replies with a friendly "model unavailable" message rather than crashing.

![Settings → Agent provider control](screenshots/settings-agent.png)

<sub>Settings → Agent — switch between vLLM (local) and the cloud opt-ins.</sub>

**Switching providers:**

- In the UI: **Settings → Agent**, pick the provider.
- Or set `LLM_PROVIDER` in the environment (overrides `config.yaml`).
- Model IDs live in `config.yaml` under `llm` (`anthropic_model`, `openai_model`); both
  stay set so switching needs no model edit. The API key still comes from the environment.
- Point the OpenAI provider at any OpenAI-compatible server with `OPENAI_BASE_URL`.

## Local vLLM (Apple Silicon)

On Apple Silicon (macOS 15+), vLLM uses the Metal GPU via
[vllm-metal](https://github.com/vllm-project/vllm-metal). Docker Desktop cannot pass
through the Metal GPU, so vLLM runs as a **host-native process** — the agent container
reaches it at `host.docker.internal:8000` (set by `vllm_base_url` in `config.yaml`).

**Default model:** `mlx-community/gemma-4-12B-it-4bit` — Gemma 4 12B instruction-tuned,
MLX 4-bit quantised (~6.7 GB, fits 24 GB unified memory, 32 K context). Linux + NVIDIA
in-container serving is tracked in [#132](https://github.com/ljakupi/admino/issues/132).

### Setup (one-time)

```bash
# Install vllm-metal — creates ~/.venv-vllm-metal
curl -fsSL https://raw.githubusercontent.com/vllm-project/vllm-metal/main/install.sh | bash
```

### Daily workflow

```bash
make vllm-pull   # download the model weights (~6.7 GB, one-time per model)
                 # Set HF_TOKEN in the environment first if the model repo is gated.
make vllm-up     # start the server (background + pidfile)
                 # Logs: tail -f data/logs/vllm-metal.log
                 # Takes 1-2 minutes for the 12B model to fully load.
make vllm-down   # stop the server
```

### Override the model or endpoint

| Variable | Default (from `config.yaml`) | Notes |
| --- | --- | --- |
| `VLLM_MODEL` | `mlx-community/gemma-4-12B-it-4bit` | Any HuggingFace MLX model ID. `vllm-pull` and `vllm-up` both honor this. |
| `VLLM_BASE_URL` | `http://host.docker.internal:8000/v1` | Change to `http://model-runner.docker.internal/engines/v1` for Docker Model Runner. |
| `VLLM_MAX_MODEL_LEN` | `32768` | Maximum sequence length in tokens. |
| `HF_TOKEN` | *(unset)* | Only for `make vllm-pull` when the model repo is gated. Never used at runtime. |

### Docker Model Runner alternative

Docker Desktop 4.62+ ships a built-in vLLM backend:

```bash
docker model install-runner --backend vllm
docker model pull mlx-community/gemma-4-12B-it-4bit
docker model run mlx-community/gemma-4-12B-it-4bit
```

Then set `VLLM_BASE_URL=http://model-runner.docker.internal/engines/v1` in `.env` (or as
an environment variable). No `make vllm-up` needed — Docker manages the lifecycle.

## `config.yaml` reference

The shipped [`config/config.yaml`](../config/config.yaml) is fully commented. The sections:

| Section | What it controls |
| --- | --- |
| `server` | Bind `host` / `port` for the ASGI server. |
| `database` | Connection pool sizing (`min_pool_size`, `max_pool_size`). |
| `llm` | `provider`, request `timeout_s`, and the cloud `*_model` IDs. |
| `auth` | `mode` — `vpn` or `token` (see below). |
| `paths` | Location of the append-only `audit_log`. |
| `files` | `allowed_paths` the `files` tool may touch, and `max_read_chars`. |
| `limits` | Guardrails: max tool calls per message, pending confirmations, message length, context window. |
| `egress` | `allowed_hosts` — the single source of truth for the outbound whitelist. |

## Authentication modes

Set under `auth.mode` in `config.yaml` (or `AUTH_MODE` in the environment):

| Mode | Behavior | When to use |
| --- | --- | --- |
| **`vpn`** *(default)* | Trusts all connections — no token required. | The out-of-the-box localhost setup: Docker publishes the API on `127.0.0.1` only, and `make run` serves on your own machine. |
| **`token`** | Requires a Bearer token on every request (`AUTH_TOKEN`). | **Required** the moment the API is reachable beyond this machine (LAN, VPN, VPS). |

> ⚠️ **`vpn` mode serves an unauthenticated API to anything that can reach the port.** The
> moment you widen the Docker `ports:` publish beyond `127.0.0.1`, switch to `token` mode
> and set a strong `AUTH_TOKEN` (≥ 48 chars, high entropy) **first**.

## Data & storage

PostgreSQL holds four things: `settings`, `permissions`, `memory` notes, and
`oauth_tokens`.

- **OAuth tokens** are stored as **encrypted ciphertext only**. The Fernet encryption key
  lives in the `OAUTH_ENCRYPTION_KEY` environment variable and is **never** persisted to
  the database. Lose the key and stored tokens are unrecoverable; rotating it requires
  re-running the [OAuth consent flow](getting-started.md#connect-your-accounts).
- **The audit log** is **append-only NDJSON on disk** (`paths.audit_log`), recording every
  decision and tool call. See [Permissions](permissions.md#append-only-audit-log).

## Egress whitelist

`egress.allowed_hosts` in `config.yaml` is the **single source of truth** for outbound
network access. In Docker mode, `entrypoint.sh` derives the container's `iptables` rules
from this list at startup; `main.py` also checks that the configured LLM provider's API
host is present. Using a cloud provider means its host must be on the list (Anthropic is
included; uncomment `api.openai.com` for OpenAI).

For the full picture of how egress containment works — the firewall, the root→non-root
privilege drop, capabilities, and known limitations — read the
**[Security Model](SECURITY.md)**.

---

See also: **[Getting Started](getting-started.md)** · **[Permissions](permissions.md)** ·
[← Docs home](README.md)
