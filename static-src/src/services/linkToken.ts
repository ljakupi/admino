/**
 * Emailed-link token service (issue #155: Reset password and Accept
 * invitation pages, opened from `{public_url}/reset-password#token=<token>`
 * and `{public_url}/accept-invitation#token=<token>`).
 *
 * The token sits in the URL fragment, so it never reaches a server log or a
 * Referer header. `readLinkToken(hash)` parses the fragment as URL search
 * params and returns `token` only when it has the shape the backend issues
 * (`secrets.token_urlsafe(32)`: 16 to 128 characters of `[A-Za-z0-9_-]`).
 * `consumeLinkToken(location, history)` reads it and, whenever there is a
 * fragment, replaces the history entry with the same path and query minus
 * the fragment, so the token leaves the address bar and the history, even
 * when it is invalid.
 */

/** Shape the backend issues: `secrets.token_urlsafe(32)`. */
const TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;

/** Parses `hash` (with or without a leading `#`) and returns its `token` param, or `null`. */
export function readLinkToken(hash: string): string | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const token = params.get('token');
  return token !== null && TOKEN_RE.test(token) ? token : null;
}

/** The `window.location` fields `consumeLinkToken` needs. */
export interface LinkLocation {
  hash: string;
  pathname: string;
  search: string;
}

/** The `window.history` method `consumeLinkToken` needs. */
export interface LinkHistory {
  replaceState: (data: unknown, unused: string, url?: string | URL | null) => void;
}

/** Reads the token from `location.hash` and strips the fragment via `history`, even when the token is invalid. */
export function consumeLinkToken(location: LinkLocation, history: LinkHistory): string | null {
  if (location.hash === '') return null;
  const token = readLinkToken(location.hash);
  history.replaceState(null, '', location.pathname + location.search);
  return token;
}
