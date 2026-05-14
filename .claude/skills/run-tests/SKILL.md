---
name: run-tests
description: Run the pytest test suite with coverage reporting. Use after writing or modifying code to verify tests pass.
argument-hint: "[optional: specific test file or module, e.g., tests/test_permissions.py]"
---

# Run Tests

Run the admino test suite and report results.

## Steps

1. **If a specific test file was given** (`$ARGUMENTS`), run only that:
   ```bash
   python -m pytest $ARGUMENTS -v --tb=short
   ```

2. **If no argument**, run the full suite with coverage:
   ```bash
   python -m pytest tests/ -v --tb=short --cov=src/admino --cov-report=term-missing
   ```

3. **Report results clearly:**
   - Total tests: passed / failed / skipped
   - Coverage percentage per module
   - If any tests failed: show the failure details and suggest fixes
   - If coverage is below 80% on core modules (permissions.py, models.py, agent.py, audit.py, server.py, config.py): flag which modules need more tests

4. **If tests fail**, do NOT try to fix them automatically. Report what failed and why. The user will decide whether to fix manually or invoke an agent.
