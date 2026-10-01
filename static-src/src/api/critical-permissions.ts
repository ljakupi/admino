import { fetchJson } from './client';
import type {
  CriticalPermissionsResponse,
  CriticalPermissionPatchResponse,
} from './types';

const BASE = '/api/org/critical-permissions';

export function getCriticalPermissions(): Promise<CriticalPermissionsResponse> {
  return fetchJson(BASE);
}

function critPath(tool: string, action: string): string {
  return `${BASE}/${encodeURIComponent(tool)}/${encodeURIComponent(action)}`;
}

/** Promotes `tool.action` to 'confirm' (pending the cooldown); needs the Org Admin's password. */
export function promoteCriticalPermission(
  tool: string,
  action: string,
  password: string,
): Promise<CriticalPermissionPatchResponse> {
  return fetchJson(critPath(tool, action), {
    method: 'PATCH',
    body: JSON.stringify({ password }),
  });
}

/** Demotes `tool.action` back to 'deny'. No password needed (reduces privilege only). */
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
