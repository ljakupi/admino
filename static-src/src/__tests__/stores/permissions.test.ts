/**
 * Permissions store tests (issue #143: the local files tool is removed).
 *
 * Covers the store's static permission knowledge, which must mirror the
 * backend: `isHardcoded` tracks the backend's immutable denials (files.delete
 * and files.overwrite are gone, every other one stays) and `getToolMeta` no
 * longer knows a `files` tool, so it falls back to the generic metadata.
 * Google Drive and OneDrive still describe their `download` action because
 * their permission rows remain (the actions come back with attachments, #192).
 * Issue #144 translates the UI: tool labels and action descriptions come from
 * the i18n catalogs and follow the active locale, while the unknown-tool
 * fallback keeps the raw tool name. The network layer (`@/api/permissions`)
 * is mocked; nothing touches `fetch`.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
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

afterEach(() => {
  setLocale('en');
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

// --- Tool copy follows the locale (issue #144) ----------------------------

describe('permissionsStore metadata lookups read own keys only', () => {
  // Tool and action names come from the server's permission table; a name
  // that matches an Object.prototype member must still get the generic
  // fallback, never an inherited property (and never a crash).
  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty'])(
    'returns the generic fallback for the tool %j',
    (tool) => {
      const store = usePermissionsStore();

      expect([store.getToolMeta(tool), store.getActionDescription(tool, 'read')]).toEqual([
        { label: tool, description: '', actions: {} },
        '',
      ]);
    },
  );

  it.each(['constructor', 'toString', '__proto__'])(
    'has no description for the gmail action %j',
    (action) => {
      const store = usePermissionsStore();

      expect(store.getActionDescription('gmail', action)).toBe('');
    },
  );
});

describe('permissionsStore tool copy follows the locale', () => {
  const DE_STRINGS: readonly unknown[] = Object.values(de);

  it('labels the memory tool "Memory" under en', () => {
    setLocale('en');

    expect(usePermissionsStore().getToolMeta('memory').label).toBe('Memory');
  });

  it('labels the memory tool with the de catalog string under de', () => {
    setLocale('de');

    const label = usePermissionsStore().getToolMeta('memory').label;

    expect(label).not.toBe('Memory');
    expect(DE_STRINGS).toContain(label);
  });

  it('describes gmail.read as "Read a message body" under en', () => {
    setLocale('en');

    expect(usePermissionsStore().getActionDescription('gmail', 'read')).toBe('Read a message body');
  });

  it('describes gmail.read with the de catalog string under de', () => {
    setLocale('de');

    const description = usePermissionsStore().getActionDescription('gmail', 'read');

    expect(description).not.toBe('Read a message body');
    expect(DE_STRINGS).toContain(description);
  });

  it('keeps the generic fallback for an unknown tool under de', () => {
    setLocale('de');

    expect(usePermissionsStore().getToolMeta('files')).toEqual({
      label: 'files',
      description: '',
      actions: {},
    });
  });
});
