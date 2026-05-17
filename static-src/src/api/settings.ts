import { fetchJson } from './client';
import type { SettingsResponse, SettingsPatch } from './types';

export async function getSettings(): Promise<SettingsResponse> {
  return fetchJson<SettingsResponse>('/api/settings');
}

export async function patchSettings(patch: SettingsPatch): Promise<SettingsResponse> {
  return fetchJson<SettingsResponse>('/api/settings', {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
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
