.PHONY: lint format format-check typecheck test check docker-build docker-up docker-down docker-logs dev-db dev-db-down migrate run clean start start-local create-superadmin create-org docker-up-local vllm-ensure vllm-pull vllm-up vllm-down docker-build-prod docker-up-prod docker-down-prod docker-logs-prod start-prod perf ttft test-proxy

# Source and package configuration
SRC_DIR    := src
TESTS_DIR  := tests
PACKAGE    := admino

# --------------------------------------------------------------------------
# Docker Compose file selection. admino runs an `agent` container plus
# Postgres. The default LLM is Infomaniak AI Services (set INFOMANIAK_API_TOKEN
# in .env), so `make start` / `make docker-up` start only postgres + agent.
# Local vLLM serving is opt-in: a CPU container (`vllm` service, multi-arch,
# cross-platform) behind the "vllm" compose profile. `make start-local`
# provisions the model weights on the first run (vllm-ensure), then brings the
# stack up together with vllm.
# NVIDIA GPU serving: swap the CPU image for the CUDA image + a GPU
# reservation (tracked in issue #132).
# docker-compose.local.yml publishes the agent on 127.0.0.1:8000 (laptop).
# --------------------------------------------------------------------------
COMPOSE_FILES := -f docker-compose.yml -f docker-compose.local.yml

# --------------------------------------------------------------------------
# Production profile (GH-156): docker-compose.prod.yml adds the Caddy TLS
# reverse proxy for ADMINO_DOMAIN (set it in .env) and leaves out
# docker-compose.local.yml, so the agent publishes no host port. The
# services are listed explicitly, so a COMPOSE_PROFILES=vllm in the
# environment can never start the local vllm container in production.
# migrate is the one-shot schema migration (GH-220) the agent waits for.
# --------------------------------------------------------------------------
PROD_COMPOSE_FILES := -f docker-compose.yml -f docker-compose.prod.yml
PROD_SERVICES      := postgres migrate agent caddy

# --------------------------------------------------------------------------
# Local vLLM container settings
# --------------------------------------------------------------------------
# VLLM_MODEL is shared with docker compose via .env, so `make` (which provisions
# the weights) and the running container never disagree on which model to serve.
# We read just this one key from .env — compose owns the rest — while a shell/CLI
# override still wins and the shipped default applies when .env is silent.
# A/B a different model by editing VLLM_MODEL in .env, then re-running `make docker-up`.
VLLM_MODEL_ENV     := $(shell sed -n 's/^VLLM_MODEL=//p' .env 2>/dev/null | tail -1 | tr -d '"')
VLLM_MODEL         ?= $(or $(VLLM_MODEL_ENV),Qwen/Qwen3-4B-Instruct-2507)
VLLM_MODELS_VOLUME := admino-vllm-models
VLLM_IMAGE         ?= vllm/vllm-openai-cpu:latest
# HuggingFace cache directory name for the configured model, e.g.
# "Qwen/Qwen3-4B-Instruct-2507" -> "models--Qwen--Qwen3-4B-Instruct-2507".
# Used to detect whether the weights are already provisioned in the volume.
VLLM_MODEL_CACHE   := models--$(subst /,--,$(VLLM_MODEL))

lint:
	python -m ruff check $(SRC_DIR)/ $(TESTS_DIR)/

format:
	python -m ruff format $(SRC_DIR)/ $(TESTS_DIR)/

format-check:
	python -m ruff format --check $(SRC_DIR)/ $(TESTS_DIR)/

typecheck:
	python -m mypy $(SRC_DIR)/$(PACKAGE)/ --strict

test:
	python -m pytest $(TESTS_DIR)/ -v --tb=short --cov=$(SRC_DIR)/$(PACKAGE) --cov-report=term-missing

# Minimum overall test coverage. CI fails the build below this; `check` enforces
# the same number locally so a green `make check` guarantees a green CI run.
COV_MIN := 90

# Performance (GH-244). Dev-only helpers: not part of `check` or CI.
# perf: the budget gate (server overhead and GET /api/chats p95) against a throwaway
#   postgres:16 container and a fake LLM. Needs Docker.
perf:
	python -m tests.perf.chat_budgets

# ttft: manual time-to-first-token and tokens/s measurement against Infomaniak.
#   Reads INFOMANIAK_API_TOKEN from the environment or, if unset, from .env
#   (that one line only; no other secret of .env is loaded).
ttft:
	python -m tests.perf.ttft

# test-proxy: the Docker test of the production Caddyfile (compression, unbuffered
#   event streams) in the official caddy image. On demand, needs Docker: without the docker CLI
#   or a running daemon the tests fail (`make check` skips them).
test-proxy:
	ADMINO_DOCKER_TESTS=1 python -m pytest $(TESTS_DIR)/test_proxy_profile.py -v --no-cov

# Full CI-parity gate bundle — the single source of truth for "are we green?".
# CI (.github/workflows/ci.yml) and the local/dev loop both run this exact target
# so the gates can never drift apart (e.g. format-check silently missing locally).
# Order matches CI: lint -> format-check -> typecheck -> tests (coverage-gated).
check: lint format-check typecheck
	python -m pytest $(TESTS_DIR)/ --tb=short --cov=$(SRC_DIR)/$(PACKAGE) --cov-report=term-missing --cov-fail-under=$(COV_MIN)

docker-build:
	docker compose $(COMPOSE_FILES) build

# docker-up: bring up postgres + agent (after the one-shot migrate service). The
# default provider (Infomaniak) is a cloud API, so no local model container is
# provisioned or started.
# (Re)start everything after a rebuild:
#   make docker-down && make docker-build && make docker-up
docker-up:
	docker compose $(COMPOSE_FILES) up -d

# docker-up-local: postgres + agent + the opt-in local vllm container, provisioning
# the vLLM model weights first if they are not already cached (see vllm-ensure).
docker-up-local: vllm-ensure
	docker compose $(COMPOSE_FILES) --profile vllm up -d

# docker-down stops every service, including vllm when it was started.
docker-down:
	docker compose $(COMPOSE_FILES) --profile vllm down

docker-logs:
	docker compose $(COMPOSE_FILES) logs -f

dev-db:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up postgres -d

dev-db-down:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down postgres

# --------------------------------------------------------------------------
# Native dev against `make dev-db` (GH-220). Both read the shell environment.
# migrate: apply pending migrations and set the runtime role's password, as the
#   database owner (PG_USER/PG_PASSWORD; PG_APP_PASSWORD for admino_app).
# run: migrate, then start the app as the runtime role admino_app
#   (PG_APP_PASSWORD), with the owner password removed from its environment.
#   It also sets ADMINO_ATTACHMENTS_ROOT (default: ./data/attachments, git-ignored,
#   created mode 0700; an exported value wins) so uploads work natively (GH-281).
# In Docker the one-shot `migrate` service does the same before the agent starts.
# --------------------------------------------------------------------------
ADMINO_ATTACHMENTS_ROOT ?= $(CURDIR)/data/attachments

migrate:
	python -m $(PACKAGE).migrate

run: migrate
	mkdir -p -m 0700 "$(ADMINO_ATTACHMENTS_ROOT)"
	chmod 700 "$(ADMINO_ATTACHMENTS_ROOT)"
	ADMINO_ATTACHMENTS_ROOT="$(ADMINO_ATTACHMENTS_ROOT)" env -u PG_PASSWORD python -m $(PACKAGE).main

clean:
	find $(SRC_DIR) $(TESTS_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache dist htmlcov .coverage

# --------------------------------------------------------------------------
# Local vLLM container — CPU-based, cross-platform (Apple Silicon + Linux)
#
# The vllm service in docker-compose.yml uses vllm/vllm-openai-cpu:latest,
# a multi-arch image (linux/arm64 + linux/amd64). Docker auto-pulls the
# correct arch — no host/OS detection required.
#
# Opt-in: the default provider is Infomaniak, so only these targets touch vllm.
# Workflow (model weights are auto-provisioned on first `start-local`):
#   make start-local # provision model if needed, then bring up postgres+agent+vllm
#   make vllm-pull   # (optional) pre-download / resume model weights explicitly
#   make vllm-down   # stop just the vllm service (agent + postgres keep running)
#
# Memory note: a 4B FP16 model needs ~8 GB RAM + KV cache. Docker Desktop
# must have ~12–16 GB allocated (Settings → Resources → Memory).
# --------------------------------------------------------------------------

# vllm-pull: download model weights into the named Docker volume.
# Uses a temporary container that has internet access (default bridge network).
# The vllm service itself runs on the internal-only network with HF_HUB_OFFLINE=1,
# so this is the one step that touches the internet.
# HF_TOKEN is optional — Qwen/Qwen3-4B-Instruct-2507 is a public model.
# Set HF_TOKEN in the environment only if you switch to a gated model.
vllm-pull:
	@echo "Downloading $(VLLM_MODEL) into volume $(VLLM_MODELS_VOLUME) (one-time download; size depends on the model)..."
	@echo "Note: HF_TOKEN is optional for public models. Set it if your model is gated."
	docker run --rm \
		-e HF_HOME=/models \
		-e HF_TOKEN \
		-v $(VLLM_MODELS_VOLUME):/models \
		--entrypoint hf \
		$(VLLM_IMAGE) \
		download "$(VLLM_MODEL)"
	@echo "Model download complete: $(VLLM_MODEL)"

# vllm-ensure: guarantee the model weights are present AND complete before serving.
# The vllm service runs offline (HF_HUB_OFFLINE=1) on the internal-only network,
# so the weights MUST be fully in the volume or the container crash-loops:
#   - empty volume             -> LocalEntryNotFoundError
#   - partial/interrupted pull  -> FileNotFoundError: weight files ... missing
# We therefore treat the model as cached only when BOTH hold:
#   1. the snapshot's config.json exists, and
#   2. there are no `*.incomplete` blobs (hf marks in-flight downloads this way).
# Checking config.json alone is not enough: it downloads early, so an interrupted
# pull leaves config.json + only some safetensors shards yet still looks "cached"
# (this exact case crash-looped the container with missing shards 1 & 2 of 3).
# The check reuses $(VLLM_IMAGE) (already required to serve), adds no new image
# dependency, and is offline-safe once the model is fully cached. `vllm-pull` is
# resumable, so a re-trigger completes a partial download rather than restarting it.
vllm-ensure:
	@if docker run --rm -v $(VLLM_MODELS_VOLUME):/models --entrypoint sh $(VLLM_IMAGE) \
		-c 'ls /models/hub/$(VLLM_MODEL_CACHE)/snapshots/*/config.json >/dev/null 2>&1 && ! find /models/hub/$(VLLM_MODEL_CACHE) -name "*.incomplete" 2>/dev/null | grep -q .' > /dev/null 2>&1; then \
		echo "vLLM weights for $(VLLM_MODEL) already cached — skipping download."; \
	else \
		echo "vLLM weights for $(VLLM_MODEL) missing or incomplete — downloading (resumable)..."; \
		$(MAKE) vllm-pull; \
	fi

# start: alias for docker-up (postgres + agent, default Infomaniak provider).
start: docker-up

# docker-build-prod: build the agent and caddy images of the production profile.
docker-build-prod:
	docker compose $(PROD_COMPOSE_FILES) build agent caddy

# docker-up-prod: postgres + migrate + agent + the Caddy TLS reverse proxy on ports 80/443.
docker-up-prod:
	docker compose $(PROD_COMPOSE_FILES) up -d $(PROD_SERVICES)

docker-down-prod:
	docker compose $(PROD_COMPOSE_FILES) down

docker-logs-prod:
	docker compose $(PROD_COMPOSE_FILES) logs -f

# start-prod: alias for docker-up-prod (production profile, see above).
start-prod: docker-up-prod

# start-local: alias for docker-up-local — adds the opt-in local vllm container
# (provisions the model on demand via vllm-ensure). Select the "vLLM" provider in
# Settings → Agent (or set llm.provider: "vllm") to chat with it.
start-local: docker-up-local

# create-superadmin: create the first Super Admin in the running agent container.
#   make create-superadmin EMAIL=you@example.ch NAME='Your Name'
# The CLI prompts for the password on the terminal (docker compose exec allocates
# a TTY), so the password never appears in argv or shell history. EMAIL and NAME
# reach the fixed argv as quoted environment variables ("$$EMAIL"), never spliced
# into the shell text. Runs as the unprivileged admino user, not root.
create-superadmin:
	@if [ -z "$$EMAIL" ] || [ -z "$$NAME" ]; then \
		echo "Usage: make create-superadmin EMAIL=you@example.ch NAME='Your Name'" >&2; \
		exit 2; \
	fi
	docker compose $(COMPOSE_FILES) exec -u admino agent \
		python -m admino.admin_cli create-superadmin --email "$$EMAIL" --name "$$NAME"

# create-org: create an organization and invite its first Org Admin (GH-154).
#   make create-org NAME='Treuhand Muster AG' ADMIN_EMAIL=admin@example.ch
# The plan limits default to 10 seats, CHF 100 a month and 10 GiB; run the CLI
# directly (python -m admino.admin_cli create-org --help) to set them. With SMTP
# configured the invitation is emailed; without it, the one-time link is printed
# on this terminal only (docker compose exec allocates a TTY). NAME and
# ADMIN_EMAIL reach the fixed argv as quoted environment variables, never
# spliced into the shell text. Runs as the unprivileged admino user, not root.
create-org:
	@if [ -z "$$NAME" ] || [ -z "$$ADMIN_EMAIL" ]; then \
		echo "Usage: make create-org NAME='Org name' ADMIN_EMAIL=admin@example.ch" >&2; \
		exit 2; \
	fi
	docker compose $(COMPOSE_FILES) exec -u admino agent \
		python -m admino.admin_cli create-org --name "$$NAME" --admin-email "$$ADMIN_EMAIL"

# vllm-up: bring up just the vllm service (useful to restart it independently).
vllm-up:
	docker compose $(COMPOSE_FILES) --profile vllm up -d vllm

# vllm-down: stop just the vllm service; leaves postgres and agent running.
vllm-down:
	docker compose $(COMPOSE_FILES) stop vllm
