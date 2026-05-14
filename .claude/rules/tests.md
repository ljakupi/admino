---
paths:
  - "tests/**/*.py"
---

# Test Code Rules

- Use pytest (no unittest.TestCase)
- Use pytest-asyncio for async tests
- Use pytest.mark.parametrize for exhaustive state testing
- Descriptive test names: test_{module}_{scenario}_{expected_outcome}
- One assertion per test (or closely related group)
- Mock external services (Ollama, Google APIs) — never make real API calls
- Use tmp_path fixture for temp files
- Shared fixtures in conftest.py
- Tests must pass with `make test`
