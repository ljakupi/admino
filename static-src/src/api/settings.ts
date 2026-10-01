/**
 * Settings API client (issue #159: settings split into platform, organization
 * and user scopes).
 *
 * The old single `/api/settings` endpoint is gone. This module wraps:
 * - `getMySettings` / `patchMySettings` -> `/api/me/settings` (the caller's
 *   own theme and notifications, every role),
 * - `resetMySettings` -> `POST /api/me/settings/reset` (issue #35: reverts
 *   the caller's own theme and notifications to the defaults; no request
 *   body),
 * - `getOrgSettings` / `patchOrgSettings` -> `/api/org/settings` (Org Admin
 *   only; anyone else gets a 403),
 * - `getOAuthStatus` -> `/api/oauth/{provider}/status`.
 * `getOAuthAuthorizeUrl` and `disconnectOAuth` are unchanged. Every call goes
 * through `fetchJson`, so it carries the session cookie and throws `ApiError`
 * on a non-2xx response. `provider` is validated before any request is made,
 * so a crafted value can never reach another path.
 */
import { fetchJson } from './client';
import type {
  OAuthConnectionStatus,
  OrgSettingsPatch,
  OrgSettingsResponse,
  UserSettingsPatch,
  UserSettingsResponse,
} from './types';

export async function getMySettings(): Promise<UserSettingsResponse> {
  return fetchJson<UserSettingsResponse>('/api/me/settings');
}

export async function patchMySettings(patch: UserSettingsPatch): Promise<UserSettingsResponse> {
  return fetchJson<UserSettingsResponse>('/api/me/settings', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

export async function resetMySettings(): Promise<UserSettingsResponse> {
  return fetchJson<UserSettingsResponse>('/api/me/settings/reset', { method: 'POST' });
}

export async function getOrgSettings(): Promise<OrgSettingsResponse> {
  return fetchJson<OrgSettingsResponse>('/api/org/settings');
}

export async function patchOrgSettings(patch: OrgSettingsPatch): Promise<OrgSettingsResponse> {
  return fetchJson<OrgSettingsResponse>('/api/org/settings', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

export async function getOAuthStatus(provider: 'google' | 'microsoft'): Promise<OAuthConnectionStatus> {
  if (provider !== 'google' && provider !== 'microsoft') {
    throw new Error('Invalid provider');
  }
  return fetchJson<OAuthConnectionStatus>(`/api/oauth/${provider}/status`);
}

export async function getOAuthAuthorizeUrl(provider: 'google' | 'microsoft' = 'google'): Promise<{ url: string }> {
  return fetchJson<{ url: string }>(`/api/oauth/${provider}/authorize`);
}

export async function disconnectOAuth(provider: 'google' | 'microsoft'): Promise<void> {
  if (provider !== 'google' && provider !== 'microsoft') {
    throw new Error('Invalid provider');
  }
  await fetchJson<{ status: string }>(`/api/oauth/${provider}`, { method: 'DELETE' });
}
