# Tools

admino ships with the tools below. They're implemented and verified end-to-end: **read**
actions run immediately, **write** actions ask you to confirm first, and a handful of
destructive actions are **denied by design**. Every call is checked by the
[permission engine](permissions.md).

## What works today

| Tool | Actions | Auth | Notes |
| --- | --- | --- | --- |
| **Gmail** | read · list · search | Google OAuth | `send` / `delete` denied by design. |
| **Google Calendar** | read · list · create | Google OAuth | `create` asks to confirm. `update` / `delete` denied. |
| **Google Drive** | read · list · search · download | Google OAuth | `download` asks to confirm. `delete` denied. |
| **Outlook mail** | read · list · search | Microsoft OAuth | `send` / `delete` denied by design. |
| **Outlook Calendar** | read · list · create | Microsoft OAuth | `create` asks to confirm. `update` / `delete` denied. |
| **OneDrive** | read · list · search · download | Microsoft OAuth | `download` asks to confirm. `delete` denied. |
| **Files** | read · list · search · write · move | none (sandboxed path) | `write` / `move` confirm; `overwrite` / `delete` denied. |
| **Memory** | store · recall · list | none (PostgreSQL) | Persistent notes. `delete` denied. |

## Authentication

- **Google** tools (Gmail, Calendar, Drive) and **Microsoft** tools (Outlook, Calendar,
  OneDrive) need a one-time OAuth connection. Set one up with
  `python -m admino.oauth_setup <google|microsoft>` — see
  [Getting Started → Connect your accounts](getting-started.md#connect-your-accounts).
- **Files** and **Memory** work without connecting any account. `files` is restricted to a
  sandboxed path (in Docker, `~/Downloads/admino` on the host, mounted at
  `/app/documents`); nothing outside it is reachable.

## How denials work

The `send`, `update`, `overwrite`, and `delete` restrictions in the table above aren't
just defaults — several are **hardcoded** in the permission engine and can't be loosened by
config. See [Permissions → Hardcoded critical denials](permissions.md#hardcoded-critical-denials)
for the exact rules and the deliberate flow for promoting a critical action (like
`gmail.send`) to *confirm*.

## Not yet implemented

These are planned and **not** in this release — don't expect them to work yet:

- **`documents`** — a document store (store / classify / search / query).
- **`search`** — web search.

Track progress on the [roadmap in the main README](../README.md).

---

See also: **[Permissions](permissions.md)** · **[Configuration](configuration.md)** ·
[← Docs home](README.md)
