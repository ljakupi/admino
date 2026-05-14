---
paths:
  - "src/admino/permissions.py"
  - "src/admino/oauth.py"
  - "src/admino/audit.py"
---

# Security-Critical Module Rules

These files are security-critical. Extra care required:

## permissions.py
- MUST NOT import from agent.py, llm.py, server.py, or any tools/ module
- check_permission() receives ONLY (tool_name: str, action: str)
- Returns ONLY Literal["allow", "confirm", "deny"]
- Pure function: no side effects, no logging, no network, no state mutation
- Hardcoded denials checked BEFORE config lookup

## oauth.py
- Never log tokens or secrets
- Access tokens in-memory only
- Refresh tokens encrypted with Fernet before disk write
- Encryption key from env var, never hardcoded

## audit.py
- File opened in append mode only ("a"), never read mode
- Sanitize args: replace credential fields with "***"
- Truncate output to 500 chars max
- No credentials in any field
