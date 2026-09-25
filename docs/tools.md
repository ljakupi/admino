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
| **Google Drive** | read · list · search | Google OAuth | `delete` denied. `download` is unavailable until chat attachments ship. |
| **Outlook mail** | read · list · search | Microsoft OAuth | `send` / `delete` denied by design. |
| **Outlook Calendar** | read · list · create | Microsoft OAuth | `create` asks to confirm. `update` / `delete` denied. |
| **OneDrive** | read · list · search | Microsoft OAuth | `delete` denied. `download` is unavailable until chat attachments ship. |
| **Memory** | store · recall · list | none (PostgreSQL) | Persistent notes. `delete` denied. |

## Authentication

- **Google** tools (Gmail, Calendar, Drive) and **Microsoft** tools (Outlook, Calendar,
  OneDrive) need a one-time OAuth connection. Set one up with
  `python -m admino.oauth_setup <google|microsoft>` — see
  [Getting Started → Connect your accounts](getting-started.md#connect-your-accounts).
- **Memory** works without connecting any account.
- No tool reads or writes your local disk, and no host directory is mounted into the container.

## How denials work

The `send`, `update`, and `delete` restrictions in the table above aren't
just defaults — several are **hardcoded** in the permission engine and can't be loosened by
config. See [Permissions → Hardcoded critical denials](permissions.md#hardcoded-critical-denials)
for the exact rules and the deliberate flow for promoting a critical action (like
`gmail.send`) to *confirm*.

## Not yet implemented

These are planned and **not** in this release — don't expect them to work yet:

- **Chat attachments** — attach files to a chat. Google Drive and OneDrive `download` come
  back here: the downloaded file becomes an attachment of the current chat.
- **`documents`** — a document store (store / classify / search / query).
- **`search`** — web search.

Track progress on the [roadmap in the main README](../README.md).

---

See also: **[Permissions](permissions.md)** · **[Configuration](configuration.md)** ·
[← Docs home](README.md)
