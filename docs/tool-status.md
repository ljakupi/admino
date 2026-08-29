# admino — Tool Implementation Status

Ground-truth assessment of which tools/actions are actually implemented and how they
are gated, for the v0.1 (Alpha) MVP. Produced for [GH-117](https://github.com/ljakupi/admino/issues/117);
feeds the README overhaul.

This doc has **two dimensions**, tracked in separate columns:

- **Gating** — the permission decision the engine applies to each action. This is
  **verified from code** (`src/admino/permissions.py`, `DEFAULT_PERMISSIONS` +
  hardcoded denials) and is deterministic; no OAuth required.
- **Runtime** — whether the action actually works end-to-end through chat, with the
  relevant account connected. This requires a **hands-on run with live OAuth** and is
  the maintainer's to confirm. Cells below are pre-filled with the **code-expected**
  status and marked `⏳ pending hands-on` until verified against a running instance.

Status legend (runtime): `✅ working` · `🟡 partial` · `🔴 broken` ·
`⛔ denied-by-design` · `🔌 needs-OAuth` · `⏳ pending hands-on`.

Gating legend: `allow` (runs without a prompt) · `confirm` (agent proposes, user
approves) · `deny (immutable)` (hardcoded, never overridable) ·
`deny (promotable)` (hardcoded deny; can be promoted to `confirm` only via the
Critical Permissions API with re-authentication + a 5-minute cooldown).

8 tools are registered via `@register_tool` and imported at startup
(`src/admino/main.py:89-101`). Registration of each action below was verified against
the `@register_tool(..., action=...)` decorators in each module. `documents` and
`search` are planned and **absent** from `src/admino/tools/` — not in this matrix.

---

## Status matrix

### Google — Gmail (`gmail`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`            | 🔌 needs-OAuth ⏳ | Read a message by id. |
| list   | yes | `allow`            | 🔌 needs-OAuth ⏳ | List recent messages. |
| search | yes | `allow`            | 🔌 needs-OAuth ⏳ | Query-based search. |
| send   | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Google — Calendar (`google_calendar`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`   | 🔌 needs-OAuth ⏳ | Read an event. |
| list   | yes | `allow`   | 🔌 needs-OAuth ⏳ | List events. |
| create | yes | `confirm` | 🔌 needs-OAuth ⏳ | Confirm-gated write — should prompt. |
| update | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Google — Drive (`google_drive`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read     | yes | `allow`   | 🔌 needs-OAuth ⏳ | Read file content. |
| list     | yes | `allow`   | 🔌 needs-OAuth ⏳ | List recent files. |
| search   | yes | `allow`   | 🔌 needs-OAuth ⏳ | Query-based search. |
| download | yes | `confirm` | 🔌 needs-OAuth ⏳ | Confirm-gated — should prompt. |

### Microsoft — Outlook mail (`outlook`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`            | 🔌 needs-OAuth ⏳ | Read a message. |
| list   | yes | `allow`            | 🔌 needs-OAuth ⏳ | List messages. |
| search | yes | `allow`            | 🔌 needs-OAuth ⏳ | Query-based search. |
| send   | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Microsoft — Outlook calendar (`outlook_calendar`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`   | 🔌 needs-OAuth ⏳ | Read an event. |
| list   | yes | `allow`   | 🔌 needs-OAuth ⏳ | List events. |
| create | yes | `confirm` | 🔌 needs-OAuth ⏳ | Confirm-gated write — should prompt. |
| update | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Microsoft — OneDrive (`onedrive`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read     | yes | `allow`   | 🔌 needs-OAuth ⏳ | Read file content. |
| list     | yes | `allow`   | 🔌 needs-OAuth ⏳ | List files. |
| search   | yes | `allow`   | 🔌 needs-OAuth ⏳ | Query-based search. |
| download | yes | `confirm` | 🔌 needs-OAuth ⏳ | Confirm-gated — should prompt. |

### Local — Files (`files`)
No OAuth required — runs against the sandboxed path. Verifiable without connecting any account.
| Action    | Registered handler | Gating (from code) | Runtime | Notes |
|-----------|:---:|--------------------|---------|-------|
| read      | yes | `allow`   | ⏳ pending hands-on | Path-validated read within the sandbox. |
| list      | yes | `allow`   | ⏳ pending hands-on | Path-validated listing. |
| search    | yes | `allow`   | ⏳ pending hands-on | Path-validated search. |
| write     | yes | `confirm` | ⏳ pending hands-on | Confirm-gated write — should prompt. |
| move      | yes | `confirm` | ⏳ pending hands-on | Confirm-gated move — should prompt. |
| overwrite | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; modeled as a denial so an attempt yields a clear audit deny. |
| delete    | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; hardcoded denial. |

### Local — Memory (`memory`)
No OAuth required — runs against PostgreSQL. Verifiable without connecting any account.
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| store  | yes | `allow`            | ⏳ pending hands-on | Store a note. |
| recall | yes | `allow`            | ⏳ pending hands-on | Recall a note. |
| list   | yes | `allow`            | ⏳ pending hands-on | List notes. |
| delete | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; hardcoded denial. |

---

## Permission gating — verified from code

Verified against `src/admino/permissions.py`. The engine (`check_permission`) evaluates
in order: input validation → immutable denials → promotable denials → config lookup →
default-deny. Gating is **independent of OAuth** and enforced regardless of what the
config/DB contains.

- **Confirm-gated writes** (agent proposes, user approves): `google_calendar.create`,
  `outlook_calendar.create`, `google_drive.download`, `onedrive.download`,
  `files.write`, `files.move`. Set to `confirm` in `DEFAULT_PERMISSIONS`; setting any of
  these to `allow` in config is **downgraded to `confirm`** (`_CONFIRM_ONLY_ACTIONS`).
- **Immutable denials** (`IMMUTABLE_DENIALS`, never overridable): `gmail.delete`,
  `google_calendar.delete`, `google_drive.delete`, `outlook.delete`,
  `outlook_calendar.delete`, `onedrive.delete`, `documents.delete`, `files.delete`,
  `files.overwrite`, `memory.delete`. Checked **before** config lookup; a YAML/API
  override is logged and ignored.
- **Promotable denials** (`PROMOTABLE_DENIALS`, deny by default): `gmail.send`,
  `outlook.send`, `google_calendar.update`, `outlook_calendar.update`. Returned as
  `deny` unless the pair is in the promoted set (via the Critical Permissions API with
  re-auth + 5-minute cooldown), in which case the engine returns `confirm` — never
  `allow`.
- **Default-deny:** any tool/action not listed resolves to `deny`.

Runtime confirmation that the confirm prompts and denials actually fire in the running
app is part of the hands-on checklist below.

---

## Hands-on QA checklist (maintainer — live OAuth)

Run the app, connect Google + Microsoft via `oauth_setup.py`, and exercise each action
through chat. Replace the runtime cell with the observed status
(`✅ / 🟡 / 🔴`) and a one-line note. File any `🔴 broken` or `🟡 partial` finding as a
separate linked bug issue referencing GH-117.

**Mail** (`gmail`, `outlook`) — with account connected:
- [ ] read — ask to read a specific message; confirm content returns.
- [ ] list — ask for recent messages; confirm a list returns.
- [ ] search — ask to search by a query; confirm results match.

**Calendar** (`google_calendar`, `outlook_calendar`):
- [ ] read — read a specific event.
- [ ] list — list upcoming events.
- [ ] create — ask to create an event; **confirm the approval prompt appears** before it's created.

**Drive / OneDrive** (`google_drive`, `onedrive`):
- [ ] read — read a file's content.
- [ ] list — list recent files.
- [ ] search — search by a query.
- [ ] download — ask to download; **confirm the approval prompt appears**.

**Files** (`files`) — sandboxed path, no OAuth:
- [ ] read / list / search within the sandbox.
- [ ] write — **confirm the approval prompt appears**; then confirm the file is written.
- [ ] move — **confirm the approval prompt appears**; then confirm the move.
- [ ] overwrite / delete — attempt and confirm the request is **denied** (hardcoded).

**Memory** (`memory`) — no OAuth:
- [ ] store / recall / list a note.
- [ ] delete — attempt and confirm it is **denied** (hardcoded).

**Denials & promotion** (any provider):
- [ ] `*.send` (gmail/outlook), calendar `update` — confirm chat requests are **denied**.
- [ ] Confirm a denied action **cannot** be overridden via Settings; promotion requires
      re-auth + cooldown and yields a **confirm prompt**, never silent execution.

Once the runtime column is filled and any bug issues are linked, this matrix is ready to
drop into the README overhaul.
