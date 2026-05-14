---
name: lint-and-fix
description: Run ruff linting, formatting, and type checking on the codebase. Use after writing code to ensure quality standards are met.
argument-hint: "[optional: specific file path, e.g., src/admino/permissions.py]"
---

# Lint, Format, and Type Check

Run all code quality checks for admino.

## Steps

1. **Format first** (auto-fixes style issues):
   ```bash
   python -m ruff format src/ tests/
   ```

2. **Lint check** (catches errors, security issues, bad patterns):
   ```bash
   python -m ruff check src/ tests/ --fix
   ```
   If `$ARGUMENTS` is provided, scope to that file instead of the full codebase.

3. **Type check** (strict mode):
   ```bash
   python -m mypy src/admino/ --strict
   ```
   If mypy is not installed, try pyright:
   ```bash
   python -m pyright src/admino/
   ```

4. **Report results:**
   - If all three pass: report "All checks passed."
   - If any fail: list the specific errors grouped by file, with line numbers.
   - For ruff errors that were auto-fixed: list what changed.
   - For type errors: explain the issue and suggest the fix.
