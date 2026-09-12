// Default request timeout. Fast endpoints (settings, health, session) use this.
// Agent-loop calls (message/confirm) pass a longer per-call timeout — see messages.ts.
const TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message?: string,
  ) {
    super(message ?? `${status} ${statusText}`);
    this.name = 'ApiError';
  }
}

// Bounds so a pathological or proxy-injected error body can never amplify into
// a huge string (client-side memory/DoS defense-in-depth): cap the number of
// error items joined, each item's length, and the final combined length.
const MAX_DETAIL_ITEMS = 10;
const MAX_MSG_LEN = 500;
const MAX_TOTAL_LEN = 1000;

function clampLen(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * Extract a human-readable message from a FastAPI error body.
 * `detail` may be a string, or a list of pydantic error objects ({loc, msg, type}).
 * Returns undefined when nothing usable is found (caller falls back to status text).
 *
 * Output is length-bounded — the backend is trusted, but the error path must not
 * be a vector for unbounded allocation from a malformed or intercepted response.
 */
export function formatErrorDetail(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === 'string') {
    const trimmed = detail.trim();
    return trimmed ? clampLen(trimmed, MAX_TOTAL_LEN) : undefined;
  }
  if (Array.isArray(detail)) {
    const msgs = detail
      .slice(0, MAX_DETAIL_ITEMS)
      .map((item) => {
        if (item && typeof item === 'object' && 'msg' in item) {
          const m = (item as { msg?: unknown }).msg;
          // Pydantic prefixes ValueError messages with "Value error, " — strip it.
          if (typeof m === 'string') {
            return clampLen(m.replace(/^Value error,\s*/i, '').trim(), MAX_MSG_LEN);
          }
        }
        return undefined;
      })
      .filter((m): m is string => !!m);
    if (msgs.length > 0) return clampLen(msgs.join('; '), MAX_TOTAL_LEN);
  }
  return undefined;
}

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('admino_auth_token');
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

export async function fetchJson<T>(
  path: string,
  init: RequestInit = {},
  timeoutMs: number = TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(path, {
      ...init,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      let message: string | undefined;
      try {
        message = formatErrorDetail(await res.json());
      } catch {
        // Non-JSON / empty error body — fall back to the status line.
      }
      throw new ApiError(res.status, res.statusText, message);
    }

    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}
