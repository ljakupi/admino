.PHONY: lint format format-check typecheck test check docker-build docker-up docker-down docker-logs dev-db dev-db-down run clean start vllm-pull vllm-up vllm-down

# Source and package configuration
SRC_DIR    := src
TESTS_DIR  := tests
PACKAGE    := admino

# --------------------------------------------------------------------------
# Docker Compose file selection. admino runs an `agent` container plus
# Postgres. Local vLLM serving runs as a CPU container (`vllm` service,
# multi-arch, cross-platform) and is activated via the "vllm" profile.
# Provision the model once with `make vllm-pull`, then use `make start`
# or `make docker-up` to bring everything up.
# NVIDIA GPU serving: swap the CPU image for the CUDA image + a GPU
# reservation (tracked in issue #132).
# --------------------------------------------------------------------------
COMPOSE_FILES := -f docker-compose.yml

# --------------------------------------------------------------------------
# Local vLLM container settings
# --------------------------------------------------------------------------
VLLM_MODEL         ?= Qwen/Qwen3-4B-Instruct-2507
VLLM_MODELS_VOLUME := admino-vllm-models
VLLM_IMAGE         ?= vllm/vllm-openai-cpu:latest

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

# Full CI-parity gate bundle — the single source of truth for "are we green?".
# CI (.github/workflows/ci.yml) and the local/dev loop both run this exact target
# so the gates can never drift apart (e.g. format-check silently missing locally).
# Order matches CI: lint -> format-check -> typecheck -> tests (coverage-gated).
check: lint format-check typecheck
	python -m pytest $(TESTS_DIR)/ --tb=short --cov=$(SRC_DIR)/$(PACKAGE) --cov-report=term-missing --cov-fail-under=$(COV_MIN)

docker-build:
	docker compose $(COMPOSE_FILES) build

docker-up:
	docker compose $(COMPOSE_FILES) --profile vllm up -d

docker-down:
	docker compose $(COMPOSE_FILES) --profile vllm down

docker-logs:
	docker compose $(COMPOSE_FILES) logs -f

dev-db:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up postgres -d

dev-db-down:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down postgres

run:
	python -m $(PACKAGE).main

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
# Workflow:
#   make vllm-pull   # one-time: download model weights into the Docker volume
#   make start       # bring up postgres + agent + vllm together
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
	@echo "Downloading $(VLLM_MODEL) into volume $(VLLM_MODELS_VOLUME) (~8 GB one-time download)..."
	@echo "Note: HF_TOKEN is optional for public models. Set it if your model is gated."
	docker run --rm \
		-e HF_HOME=/models \
		-e HF_TOKEN \
		-v $(VLLM_MODELS_VOLUME):/models \
		--entrypoint huggingface-cli \
		$(VLLM_IMAGE) \
		download "$(VLLM_MODEL)"
	@echo "Model download complete: $(VLLM_MODEL)"

# start: one-command startup — provision the model if needed, then bring up all services.
# Checks whether the volume already exists as a best-effort proxy for "is the model
# downloaded?". If the volume is missing, runs vllm-pull first.
# Cross-platform: no host/OS detection, works on Apple Silicon and Linux alike.
start:
	@if ! docker volume inspect $(VLLM_MODELS_VOLUME) > /dev/null 2>&1; then \
		echo "Volume $(VLLM_MODELS_VOLUME) not found — running vllm-pull first..."; \
		$(MAKE) vllm-pull; \
	else \
		echo "Volume $(VLLM_MODELS_VOLUME) found — skipping vllm-pull."; \
	fi
	docker compose $(COMPOSE_FILES) --profile vllm up -d

# vllm-up: bring up just the vllm service (useful to restart it independently).
vllm-up:
	docker compose $(COMPOSE_FILES) --profile vllm up -d vllm

# vllm-down: stop just the vllm service; leaves postgres and agent running.
vllm-down:
	docker compose $(COMPOSE_FILES) stop vllm
