/**
 * Route guard logic (issue #155: auth pages and role-aware route guards).
 * Pure: the router's `beforeEach` feeds it the target route and the current
 * shell role. The backend stays authoritative for every actual request.
 */
import { canAccessArea, homePath, type Area, type ShellRole } from '@/services/access';

/** The auth pages anyone (logged in or not) may reach directly. */
export const PUBLIC_PATHS: readonly string[] = [
  '/login',
  '/forgot-password',
  '/reset-password',
  '/accept-invitation',
];

/** The shape of a router `to` target that `resolveNavigation` needs. */
export interface NavigationTarget {
  path: string;
  fullPath: string;
  query: Record<string, unknown>;
  meta: { public?: boolean; area?: Area };
}

/** The result `resolveNavigation` returns to a vue-router `beforeEach`. */
export type NavigationResult = true | { path: string; query?: Record<string, string> };

const MAX_REDIRECT_LENGTH = 2048;

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/** `value` up to (not including) its first `?` or `#`. */
function pathOnly(value: string): string {
  const stops = [value.length];
  const qIdx = value.indexOf('?');
  const hIdx = value.indexOf('#');
  if (qIdx !== -1) stops.push(qIdx);
  if (hIdx !== -1) stops.push(hIdx);
  return value.slice(0, Math.min(...stops));
}

/** Whether one (raw or decoded) form of a redirect target passes the in-app path checks. */
function isInAppPath(value: string): boolean {
  if (value[0] !== '/' || value[1] === '/' || value[1] === '\\') return false;
  if (value.includes('\\')) return false;
  if (hasControlChar(value)) return false;
  return !PUBLIC_PATHS.includes(pathOnly(value));
}

/**
 * `value` is used as a `?redirect=` target only when it is an in-app path: a
 * string starting with exactly one `/` (not `//` or `/\`, both protocol-
 * relative URLs to another host), with no backslash anywhere, no control
 * character, at most 2048 characters, and not pointing back at a public auth
 * page (no open redirect, no login loop). The checks apply to the value both
 * as given and percent-decoded, so `/%2F%2Fhost` or `/%5Chost` is refused like
 * `//host`; a malformed escape is refused. Anything else is `null`.
 */
export function safeRedirect(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > MAX_REDIRECT_LENGTH) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  return isInAppPath(value) && isInAppPath(decoded) ? value : null;
}

/**
 * a) Public pages: a logged-in user never sees the login page (sent to a
 *    safe `?redirect=` or home); the other public pages are open to anyone.
 * b) A protected page while logged out: to `/login`, preserving the target
 *    as `?redirect=` when it is safe.
 * c) A protected page the role may not open: to the role's home.
 * d) Otherwise the navigation proceeds (`true`).
 */
export function resolveNavigation(to: NavigationTarget, role: ShellRole | null): NavigationResult {
  if (to.meta.public) {
    if (role === null) return true;
    if (to.path !== '/login') return true;
    const safe = safeRedirect(to.query.redirect);
    return { path: safe ?? homePath(role) };
  }

  if (role === null) {
    const safe = safeRedirect(to.fullPath);
    return safe === null ? { path: '/login' } : { path: '/login', query: { redirect: safe } };
  }

  if (canAccessArea(role, to.meta.area as Area)) return true;
  return { path: homePath(role) };
}
