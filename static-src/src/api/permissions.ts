import { fetchJson } from './client';
import type { PermissionsResponse, PermissionPatchRequest, PermissionsSummaryResponse } from './types';

/** `GET /api/org/permissions` — the caller's org matrix (Org Admin only). */
export async function getPermissions(): Promise<PermissionsResponse> {
  return fetchJson<PermissionsResponse>('/api/org/permissions');
}

/** `PATCH /api/org/permissions` — Org Admin only. */
export async function patchPermission(patch: PermissionPatchRequest): Promise<PermissionsResponse> {
  return fetchJson<PermissionsResponse>('/api/org/permissions', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

/** `GET /api/permissions/summary` — read-only effective states, every member role. */
export async function getPermissionsSummary(): Promise<PermissionsSummaryResponse> {
  return fetchJson<PermissionsSummaryResponse>('/api/permissions/summary');
}
