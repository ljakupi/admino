/**
 * Platform console API client (issue #168: Platform console UI for the Super
 * Admin; routes from #154 orgs, #167 users/metadata, #160 + #242 settings).
 *
 * Every call goes through `fetchJson` (session cookie; CSRF is enforced server-side by the same-origin
 * `Origin`/`Sec-Fetch-Site` check plus `SameSite=Strict` cookies, so the client sends no CSRF header; a non-2xx
 * answer throws an `ApiError` with `.status`/`.reason`; 202/204 resolve
 * `undefined`). Every path starts with `/api/platform/` and the responses are
 * metadata only (operator blindness).
 *
 * Path-injection guard: each org and user id must be a UUID before it is put
 * into a path; otherwise a plain `Error('Invalid id')` is thrown and no
 * request is made.
 */
import { UUID_RE } from './ids';
import { fetchJson } from './client';
import type {
  OrgInvitation,
  PlatformOrg,
  PlatformOrgCreateRequest,
  PlatformOrgCreateResponse,
  PlatformOrgLimitsPatch,
  PlatformOrgListResponse,
  PlatformOrgMetadata,
  PlatformSettings,
  PlatformSettingsPatch,
  PlatformUser,
  PlatformUserListResponse,
} from './types';

function assertUuid(id: string): string {
  if (!UUID_RE.test(id)) {
    throw new Error('Invalid id');
  }
  return id;
}

function orgPath(orgId: string, suffix = ''): string {
  return `/api/platform/orgs/${assertUuid(orgId)}${suffix}`;
}

function userPath(orgId: string, userId: string, suffix = ''): string {
  return orgPath(orgId, `/users/${assertUuid(userId)}${suffix}`);
}

/** `GET /api/platform/orgs`. */
export function listPlatformOrgs(): Promise<PlatformOrgListResponse> {
  return fetchJson<PlatformOrgListResponse>('/api/platform/orgs');
}

/** `POST /api/platform/orgs` — body exactly `body`. */
export function createPlatformOrg(body: PlatformOrgCreateRequest): Promise<PlatformOrgCreateResponse> {
  return fetchJson<PlatformOrgCreateResponse>('/api/platform/orgs', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** `PATCH /api/platform/orgs/{id}/limits` — body exactly `patch`. */
export function updatePlatformOrgLimits(orgId: string, patch: PlatformOrgLimitsPatch): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/limits'), {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

/** `POST /api/platform/orgs/{id}/deactivate` — no body. */
export function deactivatePlatformOrg(orgId: string): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/deactivate'), { method: 'POST' });
}

/** `POST /api/platform/orgs/{id}/reactivate` — no body. */
export function reactivatePlatformOrg(orgId: string): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/reactivate'), { method: 'POST' });
}

/** `POST /api/platform/orgs/{id}/deletion` — schedules the deletion, no body. */
export function schedulePlatformOrgDeletion(orgId: string): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/deletion'), { method: 'POST' });
}

/** `DELETE /api/platform/orgs/{id}/deletion` — cancels the scheduled deletion. */
export function cancelPlatformOrgDeletion(orgId: string): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/deletion'), { method: 'DELETE' });
}

/** `PATCH /api/platform/orgs/{id}/residency` — body exactly `{"enabled": enabled}`. */
export function setPlatformOrgResidency(orgId: string, enabled: boolean): Promise<PlatformOrg> {
  return fetchJson<PlatformOrg>(orgPath(orgId, '/residency'), {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
}

/** `GET /api/platform/orgs/{id}/users`. */
export function listPlatformOrgUsers(orgId: string): Promise<PlatformUserListResponse> {
  return fetchJson<PlatformUserListResponse>(orgPath(orgId, '/users'));
}

/** `GET /api/platform/orgs/{id}/metadata` — counts and sizes only. */
export function getPlatformOrgMetadata(orgId: string): Promise<PlatformOrgMetadata> {
  return fetchJson<PlatformOrgMetadata>(orgPath(orgId, '/metadata'));
}

/** `POST /api/platform/orgs/{id}/users/{userId}/deactivate` — no body. */
export function deactivatePlatformUser(orgId: string, userId: string): Promise<PlatformUser> {
  return fetchJson<PlatformUser>(userPath(orgId, userId, '/deactivate'), { method: 'POST' });
}

/** `POST /api/platform/orgs/{id}/users/{userId}/reactivate` — no body. */
export function reactivatePlatformUser(orgId: string, userId: string): Promise<PlatformUser> {
  return fetchJson<PlatformUser>(userPath(orgId, userId, '/reactivate'), { method: 'POST' });
}

/** `POST /api/platform/orgs/{id}/users/{userId}/password-reset` — 202, resolves `undefined`. */
export function resetPlatformUserPassword(orgId: string, userId: string): Promise<void> {
  return fetchJson<void>(userPath(orgId, userId, '/password-reset'), { method: 'POST' });
}

/** `POST /api/platform/orgs/{id}/users/{userId}/invitation` — body `{}` (resend) or `{"email": email}`. */
export function reinvitePlatformUser(orgId: string, userId: string, email?: string): Promise<OrgInvitation> {
  return fetchJson<OrgInvitation>(userPath(orgId, userId, '/invitation'), {
    method: 'POST',
    body: JSON.stringify(email === undefined ? {} : { email }),
  });
}

/** `GET /api/platform/settings`. */
export function getPlatformSettings(): Promise<PlatformSettings> {
  return fetchJson<PlatformSettings>('/api/platform/settings');
}

/** `PATCH /api/platform/settings` — body exactly `patch`. */
export function patchPlatformSettings(patch: PlatformSettingsPatch): Promise<PlatformSettings> {
  return fetchJson<PlatformSettings>('/api/platform/settings', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}
