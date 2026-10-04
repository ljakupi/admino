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
| **Memory** | store · recall · list | none (PostgreSQL) | Persistent notes, one set per user. `delete` denied. |

## Authentication

- **Google** tools (Gmail, Calendar, Drive) and **Microsoft** tools (Outlook, Calendar,
  OneDrive) work with your own accounts. Each user connects their own Google and Microsoft
  accounts on the **Tools** page (**My connections** → **Connect**) and can disconnect them
  there at any time. See
  [Getting Started → Connect your accounts](getting-started.md#connect-your-accounts).
- A connection belongs to the user who made it. The agent uses it only in that user's own
  chats, never in a colleague's, and nobody can connect an account for someone else.
- Org Admins and Editors connect accounts. Viewers can't chat, so they have no
  connections. A user demoted to Viewer keeps their connections, unused, until they're
  promoted back.
- The Tools page shows each service's state: active, turned off by your organization,
  restricted by data residency, or not connected. An Org Admin turns services on or off
  for the whole organization under **Organization → Settings** (**Tools and
  permissions**). A service that is off isn't offered to the agent, even when you're
  connected.
- **Data residency.** When your organization's data residency policy is on, the Google and
  Microsoft tools are disabled: the agent isn't offered them, a call to one is refused,
  and connecting a Google or Microsoft account is refused too. Connections made before are
  kept but stay inactive, and you can still disconnect them.
- **Memory** works without connecting any account. Memory notes are per user: each user
  only ever stores, recalls and lists their own notes, never a colleague's.
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
