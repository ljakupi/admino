.PHONY: lint format format-check typecheck test check docker-build docker-up docker-down docker-logs dev-db dev-db-down run clean

# Source and package configuration
SRC_DIR    := src
TESTS_DIR  := tests
PACKAGE    := admino

# --------------------------------------------------------------------------
# Local LLM backend selection.
#
# BACKEND controls which (if any) OSS LLM overlay is merged with the base
# docker-compose.yml. admino itself is provider-agnostic — set BACKEND only
# when you want a local model running inside Docker.
#
#   (unset)        Agent only. Use with proprietary providers (Anthropic, OpenAI).
#   BACKEND=ollama Agent + Ollama.        make docker-up BACKEND=ollama
# --------------------------------------------------------------------------
BACKEND ?=
COMPOSE_FILES := -f docker-compose.yml
ifeq ($(BACKEND),ollama)
  COMPOSE_FILES += -f docker-compose.ollama.yml
else ifneq ($(BACKEND),)
  $(error Unknown BACKEND '$(BACKEND)' — use 'ollama' or leave unset)
endif

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
