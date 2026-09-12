.PHONY: lint format format-check typecheck test check docker-build docker-up docker-down docker-logs dev-db dev-db-down run clean vllm-pull vllm-up vllm-down

# Source and package configuration
SRC_DIR    := src
TESTS_DIR  := tests
PACKAGE    := admino

# --------------------------------------------------------------------------
# Docker Compose file selection. admino runs a single `agent` container plus
# Postgres. Local vLLM serving on Apple Silicon (Metal) is available via the
# host-native `vllm-metal` path — see `make vllm-pull` / `make vllm-up`.
# The agent container reaches the host server at host.docker.internal:8000.
# In-container NVIDIA/CUDA serving is tracked in issue #132.
# --------------------------------------------------------------------------
COMPOSE_FILES := -f docker-compose.yml

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
	docker compose $(COMPOSE_FILES) up -d

docker-down:
	docker compose $(COMPOSE_FILES) down

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
# Apple Silicon / macOS local vLLM serving (host-native, Metal GPU)
#
# These targets manage a host-native vllm-metal process — Docker Desktop
# cannot pass through the Metal GPU, so vLLM runs directly on the host and
# the agent container reaches it at host.docker.internal:8000.
#
# Requirements: macOS 15 (Sequoia)+, Apple Silicon, arm64 Python 3.12.
# Install vllm-metal once:
#   curl -fsSL https://raw.githubusercontent.com/vllm-project/vllm-metal/main/install.sh | bash
# That creates ~/.venv-vllm-metal. These targets activate it automatically.
#
# These targets are macOS-only. On Linux, use issue #132 (NVIDIA in-container).
# --------------------------------------------------------------------------

# Default model (overridable via VLLM_MODEL env var, matching config.yaml)
VLLM_MODEL ?= mlx-community/gemma-4-12B-it-4bit
VLLM_MAX_MODEL_LEN ?= 32768
VLLM_PID_FILE := .vllm-metal.pid
VLLM_LOG_FILE := data/logs/vllm-metal.log
VLLM_VENV := $(HOME)/.venv-vllm-metal

# vllm-pull: download the MLX weights from HuggingFace (one-time, ~6.7 GB).
# Set HF_TOKEN in the environment if the model repo is gated.
vllm-pull:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "vllm-pull is for Apple Silicon (macOS) only. See issue #132 for NVIDIA/Linux."; \
		exit 1; \
	fi
	@echo "Downloading $(VLLM_MODEL) (~6.7 GB one-time download)..."
	@if [ -n "$$HF_TOKEN" ]; then \
		HF_TOKEN="$$HF_TOKEN" huggingface-cli download $(VLLM_MODEL); \
	else \
		huggingface-cli download $(VLLM_MODEL); \
	fi
	@echo "Model download complete: $(VLLM_MODEL)"

# vllm-up: start the vllm-metal server in the background (OpenAI-compatible, port 8000).
# Logs go to data/logs/vllm-metal.log; PID stored in .vllm-metal.pid.
# The 12B model takes a minute or two to load — watch logs with:
#   tail -f data/logs/vllm-metal.log
vllm-up:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "vllm-up is for Apple Silicon (macOS) only. See issue #132 for NVIDIA/Linux."; \
		exit 1; \
	fi
	@if [ -f "$(VLLM_PID_FILE)" ] && kill -0 "$$(cat $(VLLM_PID_FILE))" 2>/dev/null; then \
		echo "vllm-metal is already running (PID $$(cat $(VLLM_PID_FILE)))."; \
		exit 0; \
	fi
	@mkdir -p data/logs
	@if [ -f "$(VLLM_VENV)/bin/activate" ]; then \
		. "$(VLLM_VENV)/bin/activate" && \
		nohup vllm serve $(VLLM_MODEL) \
			--host 0.0.0.0 \
			--port 8000 \
			--max-model-len $(VLLM_MAX_MODEL_LEN) \
			>> "$(VLLM_LOG_FILE)" 2>&1 & \
		echo $$! > "$(VLLM_PID_FILE)"; \
	else \
		echo "vllm-metal venv not found at $(VLLM_VENV)."; \
		echo "Install it first: curl -fsSL https://raw.githubusercontent.com/vllm-project/vllm-metal/main/install.sh | bash"; \
		exit 1; \
	fi
	@echo "vllm-metal started (PID $$(cat $(VLLM_PID_FILE)))"
	@echo "  Serving: http://localhost:8000/v1  (agent uses host.docker.internal:8000)"
	@echo "  Model:   $(VLLM_MODEL)"
	@echo "  Logs:    tail -f $(VLLM_LOG_FILE)"
	@echo "  Note:    the 12B model takes 1-2 minutes to finish loading before it answers."

# vllm-down: stop the background vllm-metal server via the PID file.
# No-ops cleanly if the server is not running.
vllm-down:
	@if [ ! -f "$(VLLM_PID_FILE)" ]; then \
		echo "vllm-metal is not running (no PID file found)."; \
		exit 0; \
	fi
	@PID=$$(cat "$(VLLM_PID_FILE)"); \
	if kill -0 "$$PID" 2>/dev/null; then \
		kill "$$PID" && echo "vllm-metal stopped (PID $$PID)."; \
	else \
		echo "vllm-metal was not running (stale PID $$PID)."; \
	fi; \
	rm -f "$(VLLM_PID_FILE)"
