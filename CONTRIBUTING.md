# Contributing to admino

Thank you for your interest in contributing! admino is a security-first personal AI
agent, and its development process reflects that: contributions are issue-driven,
test-first, and reviewed strictly. This document defines the rules of engagement —
please read it fully before writing any code.

## Issue-Driven Development (Strict)

**Every pull request must correspond to an open, approved GitHub issue.** PRs without
a linked issue are closed without review.

1. **Existing issues** — look for issues labelled `status: ready`. Comment on the
   issue to claim it *before* you start writing code, and wait for a maintainer to
   assign it to you. This avoids duplicate work.
2. **New ideas** (features, refactors, behavior changes) — open a discussion issue
   first, describing the problem, the proposed approach, and its security
   implications. Wait for maintainer approval **before** opening any PR. Unsolicited
   feature PRs are closed regardless of quality.
3. **Bugs** — open a bug issue with reproduction steps. Small, obvious fixes still
   need the issue, but you may open the PR as soon as the issue exists.
4. **Security vulnerabilities** — do **not** open a public issue. Report them
   privately via GitHub's *Security → Report a vulnerability* (private vulnerability
   reporting) on this repository.

## Workflow

1. **Fork** the repository on GitHub.
2. **Create a feature branch** on your fork, from `develop`:

   ```bash
   git checkout develop && git pull
   git checkout -b <type>/GH-<issue-number>-<short-description>
   ```

   Branch types: `feature/`, `fix/`, `docs/`, `test/`, `chore/` — pick the one
   matching the issue's `type:` label.
3. **Write tests first**, then the implementation (see [Testing](#testing-tdd)).
4. **Run the quality gates** locally until everything is green (see below).
5. **Open a PR against `develop`** (never `main`). Reference the issue in the PR
   body (`Closes #<issue-number>`).

## Coding Standards

All of these are enforced by CI and are non-negotiable:

- **Python 3.12+** with **full type annotations** on all function signatures and
  class attributes. `mypy --strict` must pass.
- **Pydantic v2** for all validation: config, tool arguments, API request/response
  types. No hand-rolled dict validation.
- **FastAPI** for all web routing, request handling, SSE, and static file serving.
- **ruff** with the repository's strict rule set (`E, F, W, I, N, UP, S, B, A, C4,
  SIM, TCH, RUF`) — both `ruff check` and `ruff format` must be clean.
- **Parameterized SQL only.** No string interpolation or f-strings in queries, ever.
  Raw SQL must never be constructed from LLM output.
- **Subprocesses:** `subprocess.run` with `shell=False` and a hardcoded argv only.
  `eval`, `exec`, `compile`, dynamic `importlib`, and `shell=True` are banned.
- Every module has a docstring covering purpose, inputs, outputs, and security notes.
- Keep modules small, focused, and single-responsibility. No dead code, no
  speculative abstractions.
- **Frontend:** Vue 3 + TypeScript in `static-src/`; `npm run check:i18n`,
  `npm run typecheck`, `npm run test`, and `npm run build` must pass.
- **UI strings (i18n):** the PWA ships in English, German and French through the
  in-house module in `static-src/src/i18n/`. Every user-facing string — page and
  component text, `aria-label`/`title`/`placeholder`/`alt`, toasts, empty states and
  frontend error messages — goes through `t('key')` (or `useI18n()`), never a
  hardcoded literal. There is no lint rule for this, so reviewers check it.
  - Add the key to `src/i18n/locales/en.ts` (the source catalog) **and** to `de.ts`
    and `fr.ts`, with the same `{placeholder}` names. Keys are flat and dotted,
    grouped by area (`chat.*`, `settings.*`, …). Values are string literals or plural
    objects (`{ one: '{count} tool', other: '{count} tools' }`, picked with
    `t(key, { count })` via `Intl.PluralRules`) — no template literals or expressions.
  - German is Swiss Standard German (no "ß", formal "Sie"); French uses the formal
    "vous". New or changed translations get a native-speaker review before release.
  - Sentences with inline markup stay one message with `{slot}` placeholders,
    rendered through `<I18nT>` and named slots. Never use `v-html` for translations.
  - Don't translate brand names, technical identifiers (tool/action ids, env vars,
    model ids, commands) or backend/LLM content. Format dates, numbers and CHF with
    `formatDate` / `formatNumber` / `formatChf` (Swiss `*-CH` locales).
  - `npm run check:i18n` (run in CI) fails when the catalogs' keys or placeholders
    differ.

### Banned dependencies

Do not introduce any of the following — PRs adding them are rejected:

- **Agent/LLM frameworks:** LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex
- **Web frameworks other than FastAPI:** Flask, Django
- **Third-party messaging SDKs** (Slack, Telegram, Discord, WhatsApp, etc.)

admino talks to LLM providers and external APIs through its own thin, auditable
clients. New runtime dependencies of any kind need explicit maintainer approval in
the issue before the PR.

### Adding or updating a dependency

1. Get approval in the issue first. No dependency is added without it.
2. Edit `pyproject.toml`. Use an exact pin (`name==X.Y.Z`) where the file already does.
3. Run `uv lock`. To update one package only, run `uv lock --upgrade-package <name>`.
4. Run `uv sync --extra dev` to refresh your `.venv`.
5. Commit `pyproject.toml` and `uv.lock` together.

CI runs `uv lock --check` and fails when `uv.lock` is out of date with
`pyproject.toml`. CI (`uv sync --locked`) and the Docker image install only from
`uv.lock`, hash-checked, with `--no-build`: a package without a wheel fails the
install instead of being built from source. Nothing resolves a version range at
build time.

Run uv at the exact version pinned in `requirements-uv.txt` (the one CI and the Docker
build use). Older uv releases do not understand the relative `exclude-newer` below.

#### Release waiting period

Because builds no longer pick up new releases on their own, refresh the lock on
purpose, for example with `uv lock --upgrade` for the whole lock or
`uv lock --upgrade-package <name>` for one package. List every version change in the
PR.

`[tool.uv] exclude-newer = "7 days"` in `pyproject.toml` keeps a refresh from picking
up any release younger than 7 days. A malicious or broken release is usually pulled
within days, so the lock never takes one fresh. The setting is relative, so
`uv lock --check` does not depend on the date it runs. A package already locked
stays locked as the window moves on.

A security bump that needs a younger release names its packages in
`[tool.uv.exclude-newer-package]`, with a timestamp just after the fixed release's
upload time and a comment naming the advisory or the issue that approved it. Always a
timestamp, never `false` (no limit): a timestamp stops admitting newer releases once
the window moves past it, while `false` would let a later routine refresh take the
newest release of that package with no waiting period.

```toml
[tool.uv.exclude-newer-package]
# GHSA-xxxx-xxxx-xxxx: fixed in 1.2.3, released 2026-01-02. Remove at the next routine refresh.
somepackage = "2026-01-03T00:00:00Z"
```

Run `uv lock --upgrade-package <name>`, commit `pyproject.toml` and `uv.lock`
together, and remove the entry at the next routine refresh, once the release is
older than 7 days. An exact pin that no older release satisfies is handled the same
way.

#### npm: the same waiting period, by procedure

npm has no setting that the lock check enforces, so the 7-day window for
`static-src/package-lock.json` is a documented procedure, not an enforced setting.
Pass `--before` with the date 7 days ago on every refresh or bump, so npm resolves only
releases at least that old:

```bash
cd static-src
# macOS (BSD date)
npm update --package-lock-only --before="$(date -u -v-7d +%Y-%m-%d)"            # whole lock
npm update --package-lock-only --before="$(date -u -v-7d +%Y-%m-%d)" <name>      # one package
# Linux (GNU date)
npm update --package-lock-only --before="$(date -u -d '7 days ago' +%F)" <name>
```

List every version change in the PR. A security bump that needs a younger release names
the exact fixed version (`npm install --package-lock-only <name>@<fixed>`) and cites the
advisory in the PR.

`static-src/package.json` pins one transitive package with an `overrides` entry (JSON has
no comments, so the reason is here): `@trickfilm400/rollup-plugin-off-main-thread` at
`3.0.0-pre1`. `workbox-build` 7.4.1 uses this single-maintainer fork, and its output
becomes the prologue of the shipped service worker. That version was reviewed against
`@surma/rollup-plugin-off-main-thread` 2.2.3. Re-diff it against upstream before moving
the pin, and do not widen the override to a range.

#### Dependency advisory scan

The `Advisory scan` workflow (`.github/workflows/advisory-scan.yml`) runs
`osv-scanner` on every PR, on pushes to `develop` and `main`, and weekly against
`develop`. It fails when `uv.lock`, `static-src/package-lock.json` or
`requirements-uv.txt` (the pinned uv installer) contains a package version with a known
advisory in the OSV database. The scanner is CI-only:
the workflow downloads one exact release and checks its SHA-256 before running it.
To run the scan locally, download the same release from
<https://github.com/google/osv-scanner/releases> (the `osv-scanner_SHA256SUMS` file
lists the hashes), verify it, then run:

```bash
osv-scanner scan source --config=osv-scanner.toml \
  --lockfile=uv.lock --lockfile=static-src/package-lock.json \
  --lockfile=requirements-uv.txt
```

It exits 0 when clean and 1 when it finds an advisory. The normal fix is to move the
package to a fixed release (`uv lock --upgrade-package <name>`, or the `npm` commands
above in `static-src/`, with the same waiting period).

If no fixed release exists yet, the advisory can be allowlisted in `osv-scanner.toml`
at the repository root. The rules, enforced by a step in the workflow:

- Only `[[IgnoredVulns]]` entries. Any other table or key fails the job.
- Each entry has an `id` (the advisory id), a non-empty `reason`, and `ignoreUntil`
  as a TOML date (`ignoreUntil = 2026-12-01`).
- `ignoreUntil` is at most 90 days ahead. An entry is expired on its date (osv-scanner
  ignores an advisory only before 00:00 UTC of `ignoreUntil`), so an entry dated today
  or earlier fails the job even if its advisory no longer matches, so stale entries get removed.
- The entry is part of the PR and is reviewed like code. Use it for an advisory
  without a fixed release, never to silence a fixable one.

The build backend (`hatchling`) is locked too, in the `build` dependency group. Keep
its pin equal to `build-system.requires` in `pyproject.toml`.

`uv` itself is a CI and Docker build-stage tool only. It is not a runtime dependency
and the runtime image does not contain it. Its exact version and wheel hashes are in
`requirements-uv.txt`, which CI and the `Dockerfile` both install with
`pip install --require-hashes`. To bump it, regenerate the file and check that the
committed lock is still accepted:

```bash
echo 'uv==X.Y.Z' | uv pip compile - --generate-hashes --python-version 3.12 --no-header
# keep the comment header of requirements-uv.txt, replace the pin and hashes
uv lock --check
```

## Testing (TDD)

admino is built test-first — this is a workflow requirement, not a suggestion:

1. **Write tests before the implementation**, derived from the issue's acceptance
   criteria. Run them and confirm they fail.
2. Implement the minimum code to make them pass. **Never weaken, skip, or delete a
   test to go green** — the tests are the spec.
3. Mock all external services (LLM providers, Google/Microsoft APIs, network). Tests
   must never make real API calls.
4. **Frontend tests cover logic and services only, never the UI.** Vitest tests target
   Pinia stores, composables, `services/` modules and API clients: expected API
   responses, state transitions, business rules, sanitization. Don't test whether an
   element is visible, its color, size or layout, and don't mount components. Logic
   that lives in a component moves to a store, composable or service so it can be
   tested there.

Quality gates (CI runs exactly these; run them locally before pushing):

```bash
make check              # lint + format-check + typecheck + tests
```

- Backend coverage must stay **≥ 90%** (`make check` enforces `--cov-fail-under=90`).
- For frontend changes, additionally from `static-src/`:

  ```bash
  npm run check:i18n  # en/de/fr catalogs have identical keys and placeholders
  npm run typecheck
  npm run test        # Vitest logic tests: stores, composables, services, API clients
  npm run build
  ```

Exception: pure infra changes (Dockerfile, Makefile, compose files, CI) have no unit
tests — but lint/typecheck still apply, and you must describe manual verification in
the PR.

## Security Expectations

Review these before every change; violations block the PR:

- **No plaintext secrets on the filesystem.** Credentials live in environment
  variables or encrypted at rest — never in code, config committed to git, or test
  fixtures with real values.
- **No credentials in logs.** Sanitize tool arguments and API payloads before
  logging; audit-log entries must never contain tokens, keys, or passwords.
- **Permission-engine isolation.** `permissions.py` is a pure function over
  `(tool, action)` and must never import from `agent.py`, `llm*.py`, or `server.py`,
  and must never see LLM-generated context. Hardcoded denials (e.g. `gmail.send`,
  `google_drive.delete`, `memory.delete`) cannot be made configurable.
- **Access-policy isolation.** `access.py` encodes the role matrix as pure functions
  (`can(principal, capability)`): no I/O, and no imports from `agent.py`, `llm*.py`,
  `server.py` or the database layer. It stays separate from the tool permission engine.
  A `Principal` is built only by trusted server code from the session's `users` row, never
  from request data; `can()` denies any principal that isn't well formed, and
  `model_construct()` / `model_copy(update=...)` are disabled. `users.kind` and
  `users.org_id` can't change after insert (a database trigger enforces it).
- **Tenant scoping.** Every repository function for organization content takes a
  `TenantContext` (`tenancy.py`) and filters by its `org_id`; there's no unscoped
  content query. Super Admins never get a `TenantContext`, so they can't reach content.
- **Network boundaries stay intact.** The agent container is whitelist-only egress;
  local LLM containers get zero external network access. Don't loosen either.
- New tools or actions require permission entries and a security rationale in the
  issue before implementation.

## Pull Request Expectations

- One logical change per PR, matching one approved issue. Include
  `Closes #<issue-number>` in the body and fill in the PR template.
- CI must be green: `make check` (backend) and the frontend typecheck/build.
- Update documentation touched by your change (README, docstrings).
- **No self-merge.** A maintainer reviews every PR and merges it when satisfied;
  expect review feedback focused heavily on security and test quality.
- Keep commits clean and messages explanatory (what + why). The PR may be
  squash-merged at the maintainer's discretion.

## Contributor License Agreement (CLA)

Before any pull request can be merged, you must sign the
[admino Individual Contributor License Agreement](CLA.md). Signing is electronic and
takes seconds: the CLA Assistant bot comments on your first PR with instructions,
and the check blocks the merge until you have signed. You sign once; it covers all
your future contributions.

## License

admino is licensed under the [Apache License 2.0](LICENSE). By contributing, you
agree that your contributions are licensed under the same terms and as described in
the [CLA](CLA.md).
