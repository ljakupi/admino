# admino

@.claude/CLAUDE.md

## Git Workflow

- **Base branch**: `develop` (all feature work merges here; `main` is for releases only)
- **Branch naming**: `{type}/GH-{issue_number}-{short-description}`
  - Types: `feature/`, `fix/`, `chore/`, `docs/`, `refactor/`, `test/`
  - Examples: `feature/GH-12-gmail-tools`, `fix/GH-34-confirmation-hang`
- **PR conventions**: always include `Closes #XX` in the PR body to auto-close the issue on merge
- **Quality gates** (must all pass before committing):
  - `make lint` — ruff check
  - `make typecheck` — mypy strict
  - `make test` — pytest with coverage (must not drop below 93%)
- **Commit style**: concise message explaining "why", not "what"

## GitHub Integration

- Read an issue: `gh issue view <number>`
- Create a PR: `gh pr create --base develop --title "..." --body "..."`
- Always fill in the PR template (`.github/pull_request_template.md`)
- When implementing an issue, read the full issue body first for acceptance criteria

## Frontend Commands

From `static-src/` directory:
- `npm run build` — production build (outputs to `../static/`)
- `npm run typecheck` — vue-tsc type checking
- `npm run dev` — dev server on :5173 with API proxy
