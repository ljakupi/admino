.PHONY: lint format typecheck test docker-build docker-up docker-down run clean

# Source and package configuration
SRC_DIR := src
PACKAGE := admino

# Detect OS for cross-platform compatibility
UNAME := $(shell uname -s)

lint:
	ruff check $(SRC_DIR)/

format:
	ruff format $(SRC_DIR)/

typecheck:
	mypy $(SRC_DIR)/

test:
	pytest

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

run:
	uvicorn admino.main:app --reload --host 127.0.0.1 --port 8000

clean:
ifeq ($(UNAME), Darwin)
	find $(SRC_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find tests -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache dist htmlcov .coverage
else
	find $(SRC_DIR) tests -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache dist htmlcov .coverage
endif
