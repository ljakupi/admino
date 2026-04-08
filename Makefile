.PHONY: lint format typecheck test docker-build docker-up docker-down run clean

# Source and package configuration
SRC_DIR    := src
TESTS_DIR  := tests
PACKAGE    := admino

# Detect OS for cross-platform compatibility
UNAME := $(shell uname -s)

lint:
	python -m ruff check $(SRC_DIR)/ $(TESTS_DIR)/

format:
	python -m ruff format $(SRC_DIR)/ $(TESTS_DIR)/

typecheck:
	python -m mypy $(SRC_DIR)/$(PACKAGE)/ --strict

test:
	python -m pytest $(TESTS_DIR)/ -v --tb=short --cov=$(SRC_DIR)/$(PACKAGE) --cov-report=term-missing

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

run:
	python -m $(PACKAGE).main

clean:
ifeq ($(UNAME), Darwin)
	find $(SRC_DIR) $(TESTS_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache dist htmlcov .coverage
else
	find $(SRC_DIR) $(TESTS_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .pytest_cache dist htmlcov .coverage
endif
