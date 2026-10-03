/**
 * Org users and invitations API client (issue #165: Organization console,
 * users and invitations UI; the backend routes come from #153 (invitations)
 * and #164 (org users)).
 *
 * Every call goes through `fetchJson`, so it carries the session cookie
 * (`credentials: 'same-origin'`) and a non-2xx answer throws an `ApiError`
 * with `.status` and `.reason` (e.g. a 409 `{"reason": "last_admin"}`).
 * 202/204 answers resolve `undefined`.
 *
 * Path-injection guard: every `id` argument must be a UUID before it is
 * interpolated into a path. A value that isn't throws a plain
 * `Error('Invalid id')` (never an `ApiError`) and makes no request at all —
 * the same defense-in-depth shape as `api/settings.ts`'s provider check.
 */
import { fetchJson } from './client';
import type {
  MemberRole,
  OrgInvitation,
  OrgInvitationListResponse,
  OrgUser,
  OrgUserListResponse,
  OrgUserPatch,
} from './types';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUuid(id: string): string {
  if (!UUID_RE.test(id)) {
    throw new Error('Invalid id');
  }
  return id;
}

function userPath(id: string, suffix = ''): string {
  return `/api/org/users/${assertUuid(id)}${suffix}`;
}

function invitationPath(id: string, suffix = ''): string {
  return `/api/org/invitations/${assertUuid(id)}${suffix}`;
}

/** `GET /api/org/users` — the org's users and its seat usage. */
export function listOrgUsers(): Promise<OrgUserListResponse> {
  return fetchJson<OrgUserListResponse>('/api/org/users');
}

/** `PATCH /api/org/users/{id}` — sends exactly the given patch fields. */
export function updateOrgUser(id: string, patch: OrgUserPatch): Promise<OrgUser> {
  return fetchJson<OrgUser>(userPath(id), {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

/** `POST /api/org/users/{id}/deactivate` — no body. */
export function deactivateOrgUser(id: string): Promise<OrgUser> {
  return fetchJson<OrgUser>(userPath(id, '/deactivate'), { method: 'POST' });
}

/** `POST /api/org/users/{id}/reactivate` — no body. */
export function reactivateOrgUser(id: string): Promise<OrgUser> {
  return fetchJson<OrgUser>(userPath(id, '/reactivate'), { method: 'POST' });
}

/** `DELETE /api/org/users/{id}` — 204, resolves `undefined`. */
export function deleteOrgUser(id: string): Promise<void> {
  return fetchJson<void>(userPath(id), { method: 'DELETE' });
}

/** `POST /api/org/users/{id}/password-reset` — 202, resolves `undefined`. */
export function resetOrgUserPassword(id: string): Promise<void> {
  return fetchJson<void>(userPath(id, '/password-reset'), { method: 'POST' });
}

/** `POST /api/org/users/{id}/logout` — forces the user's sessions out, 204. */
export function forceLogoutOrgUser(id: string): Promise<void> {
  return fetchJson<void>(userPath(id, '/logout'), { method: 'POST' });
}

/** `GET /api/org/invitations` — the org's pending invitations. */
export function listInvitations(): Promise<OrgInvitationListResponse> {
  return fetchJson<OrgInvitationListResponse>('/api/org/invitations');
}

/** `POST /api/org/invitations` — body exactly `{"email": email, "role": role}` (201). */
export function createInvitation(email: string, role: MemberRole): Promise<OrgInvitation> {
  return fetchJson<OrgInvitation>('/api/org/invitations', {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

/** `DELETE /api/org/invitations/{id}` — 204, resolves `undefined`. */
export function revokeInvitation(id: string): Promise<void> {
  return fetchJson<void>(invitationPath(id), { method: 'DELETE' });
}

/** `POST /api/org/invitations/{id}/resend` — no body; resolves the refreshed invitation. */
export function resendInvitation(id: string): Promise<OrgInvitation> {
  return fetchJson<OrgInvitation>(invitationPath(id, '/resend'), { method: 'POST' });
}
