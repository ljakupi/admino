/**
 * Auth API client (issue #155: auth pages and role-aware app shell).
 *
 * Thin wrapper around the public and session auth endpoints for the Login,
 * Forgot password, Reset password and Accept invitation pages and the auth
 * store. Every call goes through `fetchJson`, so it sends the session cookie
 * (`credentials: 'same-origin'`) and never an `Authorization` header, and
 * errors surface as `ApiError` with the backend status (and `reason` for a
 * 422 password policy error). The 202/204 endpoints resolve `undefined`.
 *
 * The invitation token (from the emailed link's fragment) is percent-encoded
 * into exactly one path segment, so a hostile token can never add a segment,
 * a query or a fragment to the request URL.
 */
import { fetchJson } from './client';
import type { InvitationDetails, MeResponse } from './types';

export async function login(email: string, password: string): Promise<void> {
  await fetchJson<undefined>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<void> {
  await fetchJson<undefined>('/api/auth/logout', { method: 'POST' });
}

export async function getMe(): Promise<MeResponse> {
  return fetchJson<MeResponse>('/api/auth/me');
}

export async function requestPasswordReset(email: string): Promise<void> {
  await fetchJson<undefined>('/api/auth/password-reset', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  await fetchJson<undefined>('/api/auth/password-reset/confirm', {
    method: 'POST',
    body: JSON.stringify({ token, new_password: newPassword }),
  });
}

export async function getInvitation(token: string): Promise<InvitationDetails> {
  return fetchJson<InvitationDetails>(`/api/auth/invitations/${encodeURIComponent(token)}`);
}

export async function acceptInvitation(token: string, name: string, password: string): Promise<void> {
  await fetchJson<undefined>(`/api/auth/invitations/${encodeURIComponent(token)}/accept`, {
    method: 'POST',
    body: JSON.stringify({ name, password }),
  });
}
