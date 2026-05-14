---
name: security-audit
description: Run a security-focused audit on a specific file or the entire codebase. Checks for credential exposure, injection risks, permission isolation violations, and banned patterns.
argument-hint: "[optional: specific file path to audit, e.g., src/admino/oauth.py]"
allowed-tools: Read, Grep, Glob, Bash
---

# Security Audit

Perform a security-focused code review for admino.

## Target
If `$ARGUMENTS` is provided, audit that specific file. Otherwise, audit the entire `src/admino/` directory.

## Checks to Perform

### 1. Banned Patterns (CRITICAL)
Search for these — any match is a Critical finding:
```
eval(
exec(
compile(
__import__
importlib
shell=True
subprocess.run(.*shell=True
.format(  # in SQL context
f"SELECT  # f-strings in SQL
f"INSERT
f"UPDATE
f"DELETE
```

### 2. Credential Exposure
Search for these patterns in all source files AND log output:
```
token
secret
password
api_key
Bearer
refresh_token
access_token
```
Verify none appear in: audit.py log entries, error messages, print/logging statements.

### 3. Permission Engine Isolation
Verify that `src/admino/permissions.py`:
- Has NO imports from agent.py, llm.py, server.py, or tools/
- The check_permission function signature is exactly (tool_name: str, action: str)
- Returns only Literal["allow", "confirm", "deny"]
- Contains no side effects (no file I/O, no network, no logging, no global state mutation)

### 4. SQL Injection
Find all SQLite queries. Verify every one uses parameterized queries (? placeholders), never string formatting.

### 5. Path Traversal
Check image upload handling — verify filenames are sanitized (no `..`, no absolute paths, no special characters).

### 6. subprocess Safety
Find all subprocess.run calls. Verify every one has `shell=False` and uses a hardcoded command list, not user input.

## Output Format
For each finding:
- **Severity**: Critical / High / Medium / Low / Info
- **Location**: file:line
- **Issue**: One-sentence description
- **Fix**: How to resolve it
