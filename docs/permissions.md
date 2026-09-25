# Permissions

The permission engine is the heart of *"works for you, not on you."* Every tool call the
agent wants to make is checked by a small, **isolated pure function** that receives only
the `(tool, action)` pair — never the conversation, your messages, or the tool arguments.
The agent cannot see the rules, argue with them, or route around them.

![A write action pausing for approval](screenshots/confirm-chat.png)

<sub>A <code>confirm</code> action — <code>google_calendar.create</code> — pausing for your approval before it runs.</sub>

## Three outcomes: allow, confirm, deny

admino is **default-deny**: anything not explicitly allowed is denied. Each action
resolves to exactly one of three states:

| State | Meaning |
| --- | --- |
| **allow** | Runs immediately (read-only actions only). |
| **confirm** | Pauses and asks you to approve before it runs. |
| **deny** | Blocked — the agent is told it cannot do this. |

![The permissions matrix](screenshots/permissions.png)

<sub>The Permissions page — the full allow / needs-approval / denied matrix.</sub>

## Writes are never auto-allowed

State-changing actions can only ever be **confirm** or **deny** — never **allow**. If a
config file tries to set a write action to `allow`, it is **downgraded to `confirm`**. A
prompt injection that convinces the model to "just send it" still can't turn a write into
a silent action: the engine, which never sees that text, holds the line.

## Hardcoded critical denials

Some denials are **baked into the code** and cannot be overridden by config or by the
agent:

- **Never (immutable).** Every `*.delete` — across `memory`, `google_drive`, both
  calendars, `onedrive`, `documents`, Gmail, and Outlook. These are always denied, full
  stop.
- **Deny by default, at most promotable to _confirm_.** `gmail.send`, `outlook.send`, and
  calendar `update`. These stay denied unless you *deliberately* promote them through the
  Critical Permissions flow — and even then they only ever reach **confirm**, never silent
  **allow**.

These hardcoded rules live in the permission engine and are enforced regardless of what
`permissions.yaml` or the database says.

## Promoting a critical permission

![Critical permissions](screenshots/critical-permissions.png)

<sub>Settings → Danger zone → Critical permissions — the promotable denials.</sub>

Promotable criticals (like `gmail.send`) are gated behind a deliberate, high-friction
flow under **Settings → Danger zone**:

1. **Re-authentication** — you prove it's really you.
2. **A 5-minute cooldown** — a built-in pause before the change takes effect.

After promotion the action reaches **confirm** — so it *still* asks before every send. You
can never turn one of these into a silent `allow`.

## Isolation guarantees

The engine is built so it *cannot* be influenced by model output:

- `permissions.py` is a **pure function** over `(tool, action)`.
- It **never imports** from `agent.py`, `llm*.py`, or `server.py`, and never receives
  LLM-generated context.
- Hardcoded denials cannot be made configurable.

This isolation is a coding standard enforced in review — see the security expectations in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Append-only audit log

Every decision and every tool call is written to an **append-only NDJSON log** on disk.
Nothing is edited or deleted in place, so the log is a durable record of what the agent
did and what was allowed, confirmed, or denied. See
[Configuration → Data & storage](configuration.md#data--storage).

---

See also: **[Tools](tools.md)** (what each action does) ·
**[Security Model](SECURITY.md)** (network-level containment) ·
[← Docs home](README.md)
