# admino — Tool Implementation Status

Ground-truth assessment of which tools/actions are actually implemented and how they
are gated, for the v0.1 (Alpha) MVP. Produced for [GH-117](https://github.com/ljakupi/admino/issues/117);
feeds the README overhaul.

This doc has **two dimensions**, tracked in separate columns:

- **Gating** — the permission decision the engine applies to each action. This is
  **verified from code** (`src/admino/permissions.py`, `DEFAULT_PERMISSIONS` +
  hardcoded denials) and is deterministic; no OAuth required.
- **Runtime** — whether the action actually works end-to-end through chat, with the
  relevant account connected. **Verified hands-on with live Google + Microsoft OAuth on
  2026-08-29.** Two actions are broken — `outlook.read` and `onedrive.download` — both
  tracked in [#123](https://github.com/ljakupi/admino/issues/123) (over-strict Microsoft
  Graph ID validation). Everything else works or is denied-by-design.

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
| read   | yes | `allow`            | ✅ working | Returns the email content. |
| list   | yes | `allow`            | ✅ working | Lists recent messages. |
| search | yes | `allow`            | ✅ working | Query search returns matching emails. |
| send   | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Google — Calendar (`google_calendar`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`   | ✅ working | Reads an event. |
| list   | yes | `allow`   | ✅ working | Lists events. |
| create | yes | `confirm` | ✅ working | Confirm prompt appeared; event created. |
| update | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Google — Drive (`google_drive`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read     | yes | `allow`   | ✅ working | Reads file content. |
| list     | yes | `allow`   | ✅ working | Lists recent files. |
| search   | yes | `allow`   | ✅ working | Query search returns matches. |
| download | yes | `confirm` | ✅ working | Confirm prompt appeared; downloaded. |

### Microsoft — Outlook mail (`outlook`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`            | 🔴 broken | Rejects Graph message IDs containing `= + /`. Bug: [#123](https://github.com/ljakupi/admino/issues/123). |
| list   | yes | `allow`            | ✅ working | Lists messages. |
| search | yes | `allow`            | ✅ working | Query search returns matching emails. |
| send   | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Microsoft — Outlook calendar (`outlook_calendar`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read   | yes | `allow`   | ✅ working | Reads an event. |
| list   | yes | `allow`   | ✅ working | Lists events. |
| create | yes | `confirm` | ✅ working | Confirm prompt appeared; event created. |
| update | yes | `deny (promotable)` | ⛔ denied-by-design | Handler exists but the engine blocks dispatch. |

### Microsoft — OneDrive (`onedrive`)
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| read     | yes | `allow`   | ✅ working | Worked in QA. Shares the strict ID validation, so may fail on item IDs with special chars — latent, see [#123](https://github.com/ljakupi/admino/issues/123). |
| list     | yes | `allow`   | ✅ working | Lists files. |
| search   | yes | `allow`   | ✅ working | Query search returns matches. |
| download | yes | `confirm` | 🔴 broken | Rejects item IDs containing special chars. Bug: [#123](https://github.com/ljakupi/admino/issues/123). |

### Local — Files (`files`)
No OAuth required — runs against the sandboxed path. Verifiable without connecting any account.
| Action    | Registered handler | Gating (from code) | Runtime | Notes |
|-----------|:---:|--------------------|---------|-------|
| read      | yes | `allow`   | ✅ working | Path-validated read within the sandbox. |
| list      | yes | `allow`   | ✅ working | Path-validated listing. |
| search    | yes | `allow`   | ✅ working | Path-validated search. |
| write     | yes | `confirm` | ✅ working | Confirm prompt appeared; file written. |
| move      | yes | `confirm` | ✅ working | Confirm prompt appeared; file moved. |
| overwrite | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; denied — attempt yields a clear audit deny. |
| delete    | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; hardcoded denial — attempt is denied. |

### Local — Memory (`memory`)
No OAuth required — runs against PostgreSQL. Verifiable without connecting any account.
| Action | Registered handler | Gating (from code) | Runtime | Notes |
|--------|:---:|--------------------|---------|-------|
| store  | yes | `allow`            | ✅ working | Stores a note. |
| recall | yes | `allow`            | ✅ working | Recalls a note. |
| list   | yes | `allow`            | ✅ working | Lists notes. |
| delete | no  | `deny (immutable)` | ⛔ denied-by-design | No handler; hardcoded denial — attempt is denied. |

**Summary:** of 26 registered tool/actions, **22 working ✅**, **2 broken 🔴**
(`outlook.read`, `onedrive.download` → [#123](https://github.com/ljakupi/admino/issues/123)),
**8 denied-by-design ⛔** (the `send`/`update`/`delete`/`overwrite` rows above; some
tools count in more than one bucket). `onedrive.read` works today but carries the same
latent validation bug (#123).

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

**Runtime-confirmed (2026-08-29, hands-on):** confirm prompts fire for `*.create`,
`*.download`, and `files.write`/`files.move`; the hardcoded denials (`*.send`, calendar
`update`, `*.delete`, `files.overwrite`, `memory.delete`) block in-app and cannot be
overridden via Settings; promotion requires re-auth + cooldown and yields a confirm
prompt, never silent execution.

---

## Hands-on QA checklist (maintainer — live OAuth)

Run the app, connect Google + Microsoft via `oauth_setup.py`, and exercise each action
through chat. Replace the runtime cell with the observed status
(`✅ / 🟡 / 🔴`) and a one-line note. File any `🔴 broken` or `🟡 partial` finding as a
separate linked bug issue referencing GH-117.

**Mail** (`gmail`, `outlook`) — with account connected:
- [x] read — ask to read a specific message; confirm content returns. Feedback: for Gmail it is working fine, bringing back the email content. For outlook it is not working, it is giving this error "Unfortunately, I'm unable to read this specific email because the message ID contains special characters (like =, +, /) that aren't supported by the read tool's format requirements."
- [x] list — ask for recent messages; confirm a list returns. Feedback: It is working for both gmail and outlook, it is listing emails.
- [x] search — ask to search by a query; confirm results match. Feedback: It is working for both gmail and outlook, both are able to search emails based on the query.

**Calendar** (`google_calendar`, `outlook_calendar`):
- [x] read — read a specific event. Feedback: it is working for both, Outlook Calendar and Google Calendar.
- [x] list — list upcoming events. Feedback: it is working for both, Outlook Calendar and Google Calendar.
- [x] create — ask to create an event; **confirm the approval prompt appears** before it's created. Feedback: it is working for both, Outlook Calendar and Google Calendar.

**Drive / OneDrive** (`google_drive`, `onedrive`):
- [x] read — read a file's content. Feedback: it is working for both, Google Drive and OneDrive.
- [x] list — list recent files. Feedback: it is working for both, Google Drive and OneDrive.
- [x] search — search by a query. Feedback: works for both, Google Drive and OneDrive.
- [x] download — ask to download; **confirm the approval prompt appears**. Feedback: it works for google drive. However, for onedrive there is an error "The download is failing because the OneDrive item ID contains special characters that the tool doesn't accept. I'm unable to download this file directly using the available tools.".

**Files** (`files`) — sandboxed path, no OAuth:
- [x] read / list / search within the sandbox. Feedback: it is working.
- [x] write — **confirm the approval prompt appears**; then confirm the file is written. Feedback: it is working.
- [x] move — **confirm the approval prompt appears**; then confirm the move. Feedback: it is working.
- [x] overwrite / delete — attempt and confirm the request is **denied** (hardcoded). Feedback: it is working, it can't delete or overwrite it because it is denied.

**Memory** (`memory`) — no OAuth:
- [x] store / recall / list a note. Feedback: working well.
- [x] delete — attempt and confirm it is **denied** (hardcoded). Feedback: it is denied.

**Denials & promotion** (any provider):
- [x] `*.send` (gmail/outlook), calendar `update` — confirm chat requests are **denied**. Feedback: it is denied.
- [x] Confirm a denied action **cannot** be overridden via Settings; promotion requires
      re-auth + cooldown and yields a **confirm prompt**, never silent execution. Feedback: it works.

## Open bugs from this QA
- [#123](https://github.com/ljakupi/admino/issues/123) — Microsoft Graph ID validation
  rejects valid Outlook message & OneDrive item IDs (`outlook.read`, `onedrive.download`
  broken; `onedrive.read` latent). Fix in progress.

The runtime column is filled and the one bug found is linked, so this matrix is ready to
drop into the README overhaul.
