---
name: docker-verify
description: Build and verify the Docker Compose setup for admino. Checks container health, network isolation, and egress rules. Use after infrastructure changes.
disable-model-invocation: true
---

# Docker Verification

Build and verify the admino Docker Compose deployment.

admino is provider-agnostic. Pick the backend you want to verify:

- **Proprietary** (Anthropic / OpenAI): no local LLM container — run the base compose file only.
- **Ollama**: overlay `docker-compose.ollama.yml` — adds a `local-llm` service.
- **vLLM**: overlay `docker-compose.vllm.yml` — adds a `local-llm` service (GPU required).

Set `BACKEND` (or leave unset) and run the steps below. The Makefile wraps the compose file selection.

## Steps

### 1. Build
```bash
# Proprietary provider:
make docker-build
# Ollama:
make docker-build BACKEND=ollama
# vLLM:
make docker-build BACKEND=vllm
```
If build fails, report the error and stop.

### 2. Start Services
```bash
make docker-up                 # proprietary
make docker-up BACKEND=ollama  # ollama
make docker-up BACKEND=vllm    # vllm
```
Wait for containers to be healthy:
```bash
docker compose ps
```

### 3. Health Checks
- **Agent container**: `curl -s http://localhost:8000/api/health` should return 200 with `{"status": "ok", ...}`
- **Local LLM container (Ollama)**: `docker compose exec local-llm curl -s http://localhost:11434/api/tags` should return a JSON response
- **Local LLM container (vLLM)**: `docker compose exec local-llm curl -s http://localhost:8000/health` should return 200

### 4. Network Isolation (CRITICAL)
Skip this step if running without a local LLM overlay.

Verify the local LLM has NO external network access:
```bash
docker compose exec local-llm sh -c 'curl -s --connect-timeout 3 https://google.com 2>&1 || echo "BLOCKED (expected)"'
```
Expected: connection fails. If it succeeds, this is a **Critical** security failure.

### 5. Egress Whitelist
Verify agent container can reach whitelisted hosts:
```bash
docker compose exec agent curl -s --connect-timeout 5 https://oauth2.googleapis.com/.well-known/openid-configuration | head -1
```
Expected: valid JSON response.

Verify agent container CANNOT reach non-whitelisted hosts:
```bash
docker compose exec agent curl -s --connect-timeout 3 https://example.com 2>&1 || echo "BLOCKED (expected)"
```
Expected: connection fails.

### 6. Volume Mounts
Verify volumes are mounted correctly:
```bash
docker compose exec agent ls -la /app/data/db /app/data/logs /app/data/tokens /app/config /app/documents
```

### 7. Cleanup
```bash
make docker-down                 # or: make docker-down BACKEND=ollama|vllm
```

## Report
- Build: pass/fail
- Agent health: pass/fail
- Local LLM health: pass/fail/skipped (proprietary)
- Local LLM external access: blocked/NOT BLOCKED (critical if not blocked) / skipped
- Agent egress whitelist: working/broken
- Agent egress deny: blocked/NOT BLOCKED (critical if not blocked)
- Volumes: mounted/missing
