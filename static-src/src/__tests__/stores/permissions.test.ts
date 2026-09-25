/**
 * Permissions store tests (issue #143: the local files tool is removed).
 *
 * Covers the store's static permission knowledge, which must mirror the
 * backend: `isHardcoded` tracks the backend's immutable denials (files.delete
 * and files.overwrite are gone, every other one stays) and `getToolMeta` no
 * longer knows a `files` tool, so it falls back to the generic metadata.
 * Google Drive and OneDrive still describe their `download` action because
 * their permission rows remain (the actions come back with attachments, #192).
 * The network layer (`@/api/permissions`) is mocked; nothing touches `fetch`.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { usePermissionsStore } from '@/stores/permissions';

vi.mock('@/api/permissions', () => ({
  getPermissions: vi.fn(),
  patchPermission: vi.fn(),
}));

/** Mirror of IMMUTABLE_DENIALS in src/admino/permissions.py after #143. */
const BACKEND_IMMUTABLE_DENIALS: ReadonlyArray<readonly [string, string]> = [
  ['gmail', 'delete'],
  ['google_calendar', 'delete'],
  ['google_drive', 'delete'],
  ['outlook', 'delete'],
  ['outlook_calendar', 'delete'],
  ['onedrive', 'delete'],
  ['documents', 'delete'],
  ['memory', 'delete'],
];

beforeEach(() => {
  setActivePinia(createPinia());
});

describe('permissionsStore isHardcoded', () => {
  it.each(['delete', 'overwrite'])('files.%s is no longer a hardcoded denial', (action) => {
    const store = usePermissionsStore();

    expect(store.isHardcoded('files', action)).toBe(false);
  });

  it.each(BACKEND_IMMUTABLE_DENIALS)('%s.%s stays a hardcoded denial', (tool, action) => {
    const store = usePermissionsStore();

    expect(store.isHardcoded(tool, action)).toBe(true);
  });
});

describe('permissionsStore getToolMeta', () => {
  it('returns the generic fallback for the removed files tool', () => {
    const store = usePermissionsStore();

    expect(store.getToolMeta('files')).toEqual({ label: 'files', description: '', actions: {} });
  });

  it('has no action description for any former files action', () => {
    const store = usePermissionsStore();

    for (const action of ['read', 'list', 'search', 'write', 'move', 'delete', 'overwrite']) {
      expect(store.getActionDescription('files', action)).toBe('');
    }
  });

  it.each(['google_drive', 'onedrive'])('%s still describes its download action', (tool) => {
    const store = usePermissionsStore();

    expect(Object.keys(store.getToolMeta(tool).actions)).toContain('download');
    expect(store.getActionDescription(tool, 'download')).not.toBe('');
  });
});
