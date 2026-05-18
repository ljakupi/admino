---
name: implement-issue
description: Full TDD workflow for implementing a GitHub issue. Reads the issue, writes tests first, then implements against those tests, runs quality gates + security audit, commits, and opens a PR.
argument-hint: "<issue number, e.g., 14>"
---

# Implement Issue #$ARGUMENTS

End-to-end TDD implementation workflow for GitHub issue #$ARGUMENTS.

## Workflow Overview

```
Read Issue → Plan → Write Tests → Quality Gates → Implement → Quality Gates → Security Audit → Commit → PR
```

## What to Test (and What NOT to)

**DO test (unit tests only):**
- Backend logic: API endpoints, business logic, validation, permission checks, database queries, models
- Frontend logic: store logic, API client functions, state management
- Security boundaries: auth enforcement, input validation, injection prevention

**DO NOT test:**
- DevOps/infrastructure: Dockerfile, docker-compose, Makefile, CI/CD, entrypoints, iptables
- HTML/CSS: template structure, styling, layout, visual appearance
- External services directly: never make real API calls (always mock)

## Phase 1: Read & Plan

1. **Read the issue** fully:
   ```bash
   gh issue view $ARGUMENTS
   ```

2. **Understand acceptance criteria** — these drive the tests.

3. **Explore related code** using the Explore agent or Grep/Glob to understand:
   - Existing patterns in the affected modules
   - What needs to change and where
   - Test patterns from existing test files (check `tests/` for similar features)

4. **Enter plan mode** to design the approach. The plan must include:
   - Which files will be modified/created
   - What the tests will cover (derived from acceptance criteria)
   - Implementation strategy

## Phase 2: Write Tests First (TDD)

**This phase happens BEFORE any implementation code is written.**

1. **Create the feature branch** from `develop`:
   ```bash
   git checkout develop && git pull origin develop
   git checkout -b {type}/GH-$ARGUMENTS-{short-description}
   ```

2. **Write tests** using the `test-writer` agent. The tests must:
   - Be derived from the issue's acceptance criteria, NOT from implementation
   - Cover happy path, error cases, edge cases, and adversarial inputs
   - Mock external dependencies (DB, APIs, filesystem)
   - Follow existing test patterns in `tests/`
   - Use pytest, pytest-asyncio, parametrize for exhaustive state testing

3. **Run quality gates on tests:**
   ```bash
   make lint
   ```
   Fix any lint issues in test files before proceeding.

4. **Tests SHOULD FAIL at this point** (no implementation yet). That's expected and correct.
   - If tests pass without implementation, they're testing nothing — rewrite them.

## Phase 3: Implement

1. **Implement the feature** using appropriate agents (`backend-dev`, `frontend-dev`, etc.)
   - Write the minimum code needed to make the tests pass
   - Follow all code standards from `.claude/CLAUDE.md`

2. **Run ALL quality gates — must all pass:**
   ```bash
   make lint
   make typecheck
   make test
   ```
   Fix any failures before proceeding.

3. **If tests fail:** fix the implementation, NOT the tests.
   - Tests are the spec (from acceptance criteria). Implementation must satisfy them.
   - Only fix a test if it has a genuine bug (wrong mock setup, typo in assertion).

## Phase 4: Security Audit

1. **Run the security-reviewer agent** on all new/modified source files.
   Focus areas:
   - SQL injection, command injection, XSS
   - Permission bypass, auth enforcement
   - Credential exposure, information leakage
   - Input validation gaps

2. **Fix all Medium+ findings** before committing.
   - Low findings: fix if trivial, otherwise note in PR description.
   - Info findings: no action needed.

3. **Re-run quality gates** after any security fixes:
   ```bash
   make lint && make typecheck && make test
   ```

## Phase 5: Commit & PR

1. **Commit** with a concise message explaining "why":
   ```bash
   git add <specific files>
   git commit -m "..."
   ```

2. **Push and create PR:**
   ```bash
   git push -u origin {branch-name}
   gh pr create --base develop --title "..." --body "..."
   ```
   - PR body must include `Closes #$ARGUMENTS`
   - Follow the PR template at `.github/pull_request_template.md`

## Critical Rules

- **Tests drive implementation**, never the reverse.
- **Quality gates must pass** after Phase 2 (lint only), Phase 3 (all), and Phase 4 (all).
- **Security audit is mandatory** — not optional, not skippable.
- **No testing of infra/devops** — if the issue is purely infra, skip Phase 2 entirely.
- **One commit per logical unit** — separate "Add tests" from "Add implementation" if desired, or combine into one commit if the change is cohesive.
