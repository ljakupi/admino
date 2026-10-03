/**
 * My account API client (issue #166: account self-service — profile,
 * languages, timezone, personal instructions, password change, sessions).
 *
 * Thin wrapper around `/api/me*` for the account store. Every call goes
 * through `fetchJson`, so it sends the session cookie (`credentials:
 * 'same-origin'`) and never an `Authorization` header, and a non-2xx answer
 * throws an `ApiError` carrying `.status` and `.reason` (e.g. the password
 * policy's `too_short`). Nothing here ever logs a password.
 *
 * Security note: `revokeMySession` validates `id` against a UUID pattern
 * before building the URL, so a hostile id can never add a path segment, a
 * query or a fragment to the request (path-injection guard) — and makes no
 * request at all when the id doesn't match.
 */
import { fetchJson } from './client';
import type { MyAccount, MyAccountPatch, SessionListResponse, SessionSummary } from './types';

const SESSION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getMyAccount(): Promise<MyAccount> {
  return fetchJson<MyAccount>('/api/me');
}

export async function patchMyAccount(patch: MyAccountPatch): Promise<MyAccount> {
  return fetchJson<MyAccount>('/api/me', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

export async function changeMyPassword(currentPassword: string, newPassword: string): Promise<void> {
  await fetchJson<undefined>('/api/me/password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

export async function listMySessions(): Promise<SessionSummary[]> {
  const { sessions } = await fetchJson<SessionListResponse>('/api/me/sessions');
  return sessions;
}

export async function revokeMySession(id: string): Promise<void> {
  if (!SESSION_ID_RE.test(id)) throw new Error('Invalid session id');
  await fetchJson<undefined>(`/api/me/sessions/${id}`, { method: 'DELETE' });
}
