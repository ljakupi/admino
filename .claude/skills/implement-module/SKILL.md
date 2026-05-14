---
name: implement-module
description: Step-by-step workflow for implementing a new Python module in src/admino/. Ensures consistency across all modules. Use when starting work on a new module.
argument-hint: "<module name, e.g., permissions or tools/gmail>"
---

# Implement Module: $ARGUMENTS

Follow this workflow when implementing a new module for admino.

## Pre-Implementation

1. **Read the spec**: Open `final_requirements.md` and find the section relevant to `$ARGUMENTS`.
2. **Read CLAUDE.md**: Check the module layout and code standards.
3. **Check existing code**: Look at `src/admino/` for existing patterns (imports, error handling, model definitions). Follow the same style.
4. **Identify dependencies**: What other modules does this one import from? What imports from this one? Check the module layout in CLAUDE.md for boundaries.

## Implementation Steps

1. **Create the file** at the correct path (e.g., `src/admino/$ARGUMENTS.py`).

2. **Write the module docstring** first:
   ```python
   """
   Module purpose in one sentence.

   Security notes:
   - Any security-relevant behavior documented here.
   - Import restrictions, data handling notes, etc.
   """
   ```

3. **Define Pydantic models** (or import from models.py if shared):
   - All fields typed
   - Constraints via Field() (max_length, ge, le, pattern)
   - Validators where needed

4. **Implement public functions**:
   - Full type annotations (params + return type)
   - Docstring with purpose, params, returns, raises
   - Specific exception handling (no bare except)
   - Async where appropriate (httpx calls, I/O)

5. **Run quality checks**:
   ```bash
   python -m ruff check src/admino/$ARGUMENTS.py
   python -m ruff format src/admino/$ARGUMENTS.py
   python -m mypy src/admino/$ARGUMENTS.py --strict
   ```

6. **Report what was built**:
   - List all public functions/classes created
   - Note any design decisions made
   - List what tests should be written (for the test-writer agent)

## Quality Checklist
Before finishing:
- [ ] Module docstring present
- [ ] All functions have type annotations
- [ ] All public functions have docstrings
- [ ] No `Any` types without justification
- [ ] Error handling uses specific exceptions
- [ ] No banned patterns (eval, exec, shell=True, etc.)
- [ ] ruff passes
- [ ] mypy/pyright passes in strict mode
