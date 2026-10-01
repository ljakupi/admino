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
 * fallback keeps the raw tool name.
 *
 * Issue #161 (permissions per organization): the store also loads the
 * read-only summary every member role sees (`GET /api/permissions/summary`
 * through `getPermissionsSummary()`):
 * - new state `summary` (the summary entries, `[]` at first),
 *   `summaryLoading` (false at first) and `summaryError` (null at first);
 * - `loadSummary()` fills `summary` with the response's entries (states
 *   allow / confirm / deny / disabled kept as given); `summaryLoading` is true
 *   only while the request is in flight; a failure sets `summaryError` to a
 *   non-empty message and a later successful load clears it;
 * - `summaryGroups`: a Map tool -> entries, keyed in the order the tools first
 *   appear in the response, each group keeping the response order.
 * `loadPermissions()` keeps reading the org matrix through `getPermissions()`
 * (whose path, `/api/org/permissions`, is pinned in `api/permissions.test.ts`).
 *
 * The network layer (`@/api/permissions`) is mocked; nothing touches `fetch`.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { ApiError } from '@/api/client';
import { getPermissions, getPermissionsSummary } from '@/api/permissions';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { usePermissionsStore } from '@/stores/permissions';
import type { PermissionsResponse, PermissionsSummaryResponse } from '@/api/types';

vi.mock('@/api/permissions', () => ({
  getPermissions: vi.fn(),
  patchPermission: vi.fn(),
  getPermissionsSummary: vi.fn(),
}));

const mockedGetPermissions = vi.mocked(getPermissions);
const mockedGetSummary = vi.mocked(getPermissionsSummary);

type SummaryEntry = PermissionsSummaryResponse['permissions'][number];

const SUMMARY_ENTRIES: SummaryEntry[] = [
  { tool: 'memory', action: 'get', state: 'allow' },
  { tool: 'gmail', action: 'delete', state: 'deny' },
  { tool: 'gmail', action: 'list', state: 'allow' },
  { tool: 'gmail', action: 'send', state: 'confirm' },
  { tool: 'onedrive', action: 'read', state: 'disabled' },
  { tool: 'memory', action: 'set', state: 'confirm' },
];

/** A promise the test settles by hand. Pre-implementation nobody may consume it. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

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
  mockedGetPermissions.mockReset();
  mockedGetSummary.mockReset();
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

// --- Read-only summary (issue #161) ----------------------------------------

describe('permissionsStore summary state', () => {
  it('starts with an empty summary, not loading and no error', () => {
    const store = usePermissionsStore();

    expect({
      summary: store.summary,
      summaryLoading: store.summaryLoading,
      summaryError: store.summaryError,
      groups: store.summaryGroups instanceof Map ? store.summaryGroups.size : 'not a Map',
    }).toStrictEqual({ summary: [], summaryLoading: false, summaryError: null, groups: 0 });
  });
});

describe('permissionsStore loadSummary', () => {
  it('requests the summary once and fills summary with its entries, disabled ones included', async () => {
    mockedGetSummary.mockResolvedValueOnce({ permissions: SUMMARY_ENTRIES });
    const store = usePermissionsStore();

    await store.loadSummary();

    expect({
      calls: mockedGetSummary.mock.calls.length,
      matrixCalls: mockedGetPermissions.mock.calls.length,
      summary: store.summary,
      summaryError: store.summaryError,
    }).toStrictEqual({ calls: 1, matrixCalls: 0, summary: SUMMARY_ENTRIES, summaryError: null });
  });

  it('groups the summary by tool in the order the tools first appear in the response', async () => {
    mockedGetSummary.mockResolvedValueOnce({ permissions: SUMMARY_ENTRIES });
    const store = usePermissionsStore();

    await store.loadSummary();

    expect([...store.summaryGroups.entries()]).toStrictEqual([
      [
        'memory',
        [
          { tool: 'memory', action: 'get', state: 'allow' },
          { tool: 'memory', action: 'set', state: 'confirm' },
        ],
      ],
      [
        'gmail',
        [
          { tool: 'gmail', action: 'delete', state: 'deny' },
          { tool: 'gmail', action: 'list', state: 'allow' },
          { tool: 'gmail', action: 'send', state: 'confirm' },
        ],
      ],
      ['onedrive', [{ tool: 'onedrive', action: 'read', state: 'disabled' }]],
    ]);
  });

  it('does not touch the org matrix (permissions) state', async () => {
    const matrix: PermissionsResponse = { permissions: [{ tool: 'gmail', action: 'list', permission: 'allow' }] };
    mockedGetPermissions.mockResolvedValueOnce(matrix);
    mockedGetSummary.mockResolvedValueOnce({ permissions: SUMMARY_ENTRIES });
    const store = usePermissionsStore();
    await store.loadPermissions();

    await store.loadSummary();

    expect({ permissions: store.permissions, summaryCount: store.summary.length }).toStrictEqual({
      permissions: matrix.permissions,
      summaryCount: SUMMARY_ENTRIES.length,
    });
  });

  it('is loading while the request is in flight and not loading after it succeeds', async () => {
    const pending = deferred<PermissionsSummaryResponse>();
    mockedGetSummary.mockReturnValueOnce(pending.promise);
    const store = usePermissionsStore();

    const run = store.loadSummary();
    const during = store.summaryLoading;
    pending.resolve({ permissions: SUMMARY_ENTRIES });
    await run;

    expect({ during, after: store.summaryLoading }).toStrictEqual({ during: true, after: false });
  });

  it('sets summaryError and stops loading when the request fails', async () => {
    mockedGetSummary.mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Forbidden'));
    const store = usePermissionsStore();

    await store.loadSummary();

    expect({
      calls: mockedGetSummary.mock.calls.length,
      hasError: typeof store.summaryError === 'string' && store.summaryError.trim() !== '',
      summaryLoading: store.summaryLoading,
      summary: store.summary,
    }).toStrictEqual({ calls: 1, hasError: true, summaryLoading: false, summary: [] });
  });

  it('sets summaryError on a network failure (non-ApiError) too', async () => {
    mockedGetSummary.mockRejectedValueOnce('boom');
    const store = usePermissionsStore();

    await store.loadSummary();

    expect({
      calls: mockedGetSummary.mock.calls.length,
      hasError: typeof store.summaryError === 'string' && store.summaryError.trim() !== '',
      summaryLoading: store.summaryLoading,
    }).toStrictEqual({ calls: 1, hasError: true, summaryLoading: false });
  });

  it('clears an earlier summaryError when a later load succeeds', async () => {
    mockedGetSummary
      .mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'))
      .mockResolvedValueOnce({ permissions: SUMMARY_ENTRIES });
    const store = usePermissionsStore();
    await store.loadSummary();
    if (store.summaryError === null) throw new Error('test setup: expected a summary error');

    await store.loadSummary();

    expect({ summaryError: store.summaryError, summaryCount: store.summary.length }).toStrictEqual({
      summaryError: null,
      summaryCount: SUMMARY_ENTRIES.length,
    });
  });

  it('does not let the summary failure touch the matrix error', async () => {
    mockedGetSummary.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    const store = usePermissionsStore();

    await store.loadSummary();

    expect({ calls: mockedGetSummary.mock.calls.length, error: store.error }).toStrictEqual({ calls: 1, error: null });
  });
});
