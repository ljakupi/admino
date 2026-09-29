// Default request timeout. Fast endpoints (settings, health, session) use this.
// Agent-loop calls (message/confirm) pass a longer per-call timeout — see messages.ts.
const TIMEOUT_MS = 30_000;

// Statuses whose success body is intentionally empty (issue #155: login, logout,
// password-reset confirm, invitation accept answer 204; password-reset request
// answers 202). `fetchJson` resolves `undefined` for these without ever reading
// the body, so a caller can't accidentally try to parse a body that isn't there.
const NO_BODY_STATUSES: ReadonlySet<number> = new Set([202, 204]);

// A `reason` is only ever a short snake_case code the backend emits on purpose
// (e.g. the password policy's `too_short`) — never free text. Anything else
// (wrong type, wrong shape, wrong charset/length) leaves `reason` undefined, so
// a hostile or malformed body can never smuggle text through it.
const REASON_RE = /^[a-z_]{1,40}$/;

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message?: string,
    public reason?: string,
  ) {
    super(message ?? `${status} ${statusText}`);
    this.name = 'ApiError';
  }
}

/** A 401 from any non-auth endpoint calls this once, then the caller still gets the ApiError. */
type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Registers (or, with `null`, unregisters) the app-wide 401 handler. See {@link fetchJson}. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
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

/**
 * Extract `ApiError.reason` from a FastAPI error body: only a top-level string
 * `reason` matching {@link REASON_RE}. See the module doc for why.
 */
export function extractReason(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const reason = (body as { reason?: unknown }).reason;
  return typeof reason === 'string' && REASON_RE.test(reason) ? reason : undefined;
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
      credentials: 'same-origin',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      let message: string | undefined;
      let reason: string | undefined;
      try {
        const body: unknown = await res.json();
        message = formatErrorDetail(body);
        reason = extractReason(body);
      } catch {
        // Non-JSON / empty error body — fall back to the status line.
      }

      if (res.status === 401 && !path.startsWith('/api/auth/') && unauthorizedHandler) {
        try {
          unauthorizedHandler();
        } catch {
          // A throwing handler must never replace the ApiError thrown below.
        }
      }

      throw new ApiError(res.status, res.statusText, message, reason);
    }

    if (NO_BODY_STATUSES.has(res.status)) {
      return undefined as T;
    }

    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}
