## Summary
<!-- What does this PR do and why? Link the issue: Closes #XX -->

## Changes
<!-- Bulleted list of key changes -->

## Testing
<!-- How was this tested? -->
- [ ] `make test` passes (1043+ tests)
- [ ] `make lint` passes
- [ ] `make typecheck` passes
- [ ] New tests added for new functionality
- [ ] Manual testing performed (describe below)

## Checklist
- [ ] Branch is based on `develop`
- [ ] No secrets or credentials in code
- [ ] Pydantic models used for all new data structures
- [ ] Credential redaction patterns updated if new token types introduced
- [ ] Permission entries added for new tools (if applicable)
- [ ] New UI strings go through `t()` with EN/DE/FR entries; `npm run check:i18n` passes (if applicable)
