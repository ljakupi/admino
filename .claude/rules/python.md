---
paths:
  - "src/**/*.py"
---

# Python Code Rules

- Python 3.12+ syntax (use `X | Y` union types, not `Union[X, Y]`)
- Full type annotations on all function signatures, return types, class attributes
- Pydantic v2 BaseModel for all structured data
- Field() with constraints on user-facing fields
- Module docstring on every file
- Function docstring on every public function
- No bare `except:` — catch specific exceptions
- Use `from __future__ import annotations` if needed for forward refs
- Imports organized: stdlib → third-party → local (ruff handles this)
