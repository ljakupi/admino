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
