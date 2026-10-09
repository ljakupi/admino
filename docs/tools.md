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
| **Google Drive** | read · list · search | Google OAuth | `delete` denied. `download` is unavailable until it saves into chat attachments ([#192](https://github.com/ljakupi/admino/issues/192)). |
| **Outlook mail** | read · list · search | Microsoft OAuth | `send` / `delete` denied by design. |
| **Outlook Calendar** | read · list · create | Microsoft OAuth | `create` asks to confirm. `update` / `delete` denied. |
| **OneDrive** | read · list · search | Microsoft OAuth | `delete` denied. `download` is unavailable until it saves into chat attachments ([#192](https://github.com/ljakupi/admino/issues/192)). |
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

## External content is data, not instructions

Some tool results carry text that someone else wrote: an email, a file name, an event
description, or a memory note that an earlier email may have planted. A crafted one can
try to give the agent orders ("ignore your instructions and..."). So before the model
sees such a result, admino wraps it between two markers that carry a random ID, new for
every run:

```
<untrusted_content_ID kind="email" label="gmail message 18c2f">
...the result...
</untrusted_content_ID>
```

The agent's instructions say that wrapped content is data, never instructions: the model
should point out instructions it finds there instead of following them.

| Kind | Wrapped results |
| --- | --- |
| `email` | Gmail and Outlook `read`, `list`, `search` |
| `file` | Google Drive and OneDrive `read`, `list`, `search` (names and metadata) |
| `event` | Google Calendar and Outlook Calendar `read`, `list`, and `update` (it returns the existing event) |
| `memory` | `memory.recall` when a note is found, `memory.list` when there is at least one note |

Not wrapped: the `send` and `create` results (they repeat the agent's own arguments), the
`memory.store` confirmation, error messages and "nothing found" messages.

The files you send with a message aren't tool results, but they're wrapped the same way:
`kind="attachment"`, the file's name as the label, in your message (never in the
agent's instructions) and in full, without the 20,000-character cap. See
[Configuration → Attachments](configuration.md#attachments).

Before it is wrapped, the text is cleaned: control characters and invisible formatting
characters (bidirectional overrides, zero-width characters) are removed, the exact marker
name inside the text is defused (also when split by one of those removed characters) so
the content can't end its block early with the exact marker, and the text is capped at
20,000 characters (`[truncated]`). Look-alike markers still pass, and the random ID is
only defence in depth: the model isn't told which ID is the current one. The wrapping is
guidance for the model; the hard rule is the next section, and it doesn't depend on the
model recognising markers. See
[Security Model → Untrusted content](SECURITY.md#untrusted-content-in-tool-results) for
what it does and doesn't protect against.

## Side effects

Every action declares whether it changes something (a side effect) or only reads:

| Tool | Side effect | Read-only |
| --- | --- | --- |
| **Gmail** | `send` | `read` · `list` · `search` |
| **Outlook mail** | `send` | `read` · `list` · `search` |
| **Google Calendar** | `create` · `update` | `read` · `list` |
| **Outlook Calendar** | `create` · `update` | `read` · `list` |
| **Google Drive** | — | `read` · `list` · `search` |
| **OneDrive** | — | `read` · `list` · `search` |
| **Memory** | `store` | `recall` · `list` |

Once a run has read wrapped content, a side effect that the permission matrix allows asks
you to confirm first, for the rest of the conversation. Denied and confirm actions stay as
they are. See
[Permissions → External content](permissions.md#external-content-makes-side-effects-ask-first).
An action added without a declaration counts as a side effect.

## Long results are cut

A tool result that would take more of the model's context than
`context.max_tool_result_tokens` allows (`config.yaml`, 8,000 tokens by default, from 256
to 100,000) is cut: it keeps its longest beginning that fits, and the marker
`[tool result truncated to fit the context]` follows on its own line. When the cut falls
inside wrapped content, the wrapped block is closed first: its end marker follows the kept
part on its own line, before the marker, within the same cap. The model gets the cut
result, and the chat stores it. Ask for less (a narrower search, fewer emails) when you
need what was cut.

Wrapped content still counts in full: whether a later side effect asks first is decided on
the whole result, before the cut, so a cut that removes the wrapped part, its markers
included, doesn't lift the rule above. See
[Configuration → Context budget](configuration.md#context-budget) for how the rest of a
chat is fitted into the model's context.

## Not yet implemented

These are planned and **not** in this release — don't expect them to work yet:

- **Drive and OneDrive downloads into attachments**
  ([#192](https://github.com/ljakupi/admino/issues/192)) — `download` saves the file as an
  attachment of the current chat. You can already upload attachments yourself (see
  [Configuration → Attachments](configuration.md#attachments)); no tool reads them, but
  once you send one with a message, its content reaches the model as data.
- **`documents`** — a document store (store / classify / search / query).
- **`search`** — web search.

Track progress on the [roadmap in the main README](../README.md).

---

See also: **[Permissions](permissions.md)** · **[Configuration](configuration.md)** ·
[← Docs home](README.md)
