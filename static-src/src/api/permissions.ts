import { fetchJson } from './client';
import type { PermissionsResponse, PermissionPatchRequest } from './types';

export async function getPermissions(): Promise<PermissionsResponse> {
  return fetchJson<PermissionsResponse>('/api/permissions');
}

export async function patchPermission(patch: PermissionPatchRequest): Promise<PermissionsResponse> {
  return fetchJson<PermissionsResponse>('/api/permissions', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}
