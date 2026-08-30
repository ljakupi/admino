# README screenshots

Drop the app screenshots referenced by the root `README.md` here. Capture them from a
running instance (`make dev-db && make run`, then open `localhost:8000`).

Expected files (exact names — the README links to these paths):

| File | Page | How to reach it |
| --- | --- | --- |
| `chat.png` | Chat | Default view at `localhost:8000` — show a message with a tool call. |
| `settings-agent.png` | Settings → Agent | Settings → **Agent**; show the provider control (vLLM *coming soon* / Claude / OpenAI). |
| `permissions.png` | Permissions | Permissions page — the allow / needs-approval / denied matrix. |
| `critical-permissions.png` | Critical permissions | Settings → **Danger zone** → the Critical permissions card (promotable denials). |

Notes:

- Screenshots capture **real UI state**, so review each for anything sensitive (message
  content, account names, tokens) before committing.
- Keep them reasonably sized (PNG, ideally < ~500 KB each). Crop to the app window.
- If you rename a file, update the matching link in the root `README.md`.
