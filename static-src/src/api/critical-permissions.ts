import { fetchJson } from './client';
import type {
  CriticalPermissionsResponse,
  CriticalPermissionPatchResponse,
} from './types';

export function getCriticalPermissions(): Promise<CriticalPermissionsResponse> {
  return fetchJson('/api/critical-permissions');
}

function critPath(tool: string, action: string): string {
  return `/api/critical-permissions/${encodeURIComponent(tool)}/${encodeURIComponent(action)}`;
}

export function promoteCriticalPermission(
  tool: string,
  action: string,
  bearerToken: string,
): Promise<CriticalPermissionPatchResponse> {
  return fetchJson(critPath(tool, action), {
    method: 'PATCH',
    body: JSON.stringify({ bearer_token: bearerToken }),
  });
}

export function demoteCriticalPermission(
  tool: string,
  action: string,
): Promise<CriticalPermissionPatchResponse> {
  return fetchJson(critPath(tool, action), {
    method: 'PATCH',
  });
}

export function cancelPendingPromotion(
  tool: string,
  action: string,
): Promise<CriticalPermissionPatchResponse> {
  return fetchJson(`${critPath(tool, action)}/pending`, {
    method: 'DELETE',
  });
}
