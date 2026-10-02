/**
 * Org services store tests (issue #162: the Org Admin's service switches move
 * from the Tools page to the Organization console).
 *
 * `useOrgServicesStore` (Pinia id 'orgServices') owns the organization's
 * seven tool switches, which moved out of the settings store (GH-162 §14):
 * - state: `tools` (all seven on), `dataResidency` (initially TRUE: the
 *   residency lock fails closed until the server says otherwise) and
 *   `loaded` (false).
 * - `load()`: `GET /api/org/settings` -> `tools`, `dataResidency`
 *   (`data_residency`), `loaded = true`. A failure keeps the current state,
 *   leaves `loaded` false and never throws.
 * - `isLocked(tool)`: `isResidencyLocked(tool, dataResidency)`: the six
 *   Google/Microsoft tools under residency; `memory` never.
 * - `setEnabled(tool, enabled)`: a locked tool makes no API call and changes
 *   nothing. Otherwise the switch flips optimistically and
 *   `PATCH /api/org/settings` gets exactly `{ tools: { [tool]: enabled } }`;
 *   success applies the response's `tools` and `data_residency` and toasts
 *   "Saved"; failure reverts only that tool and shows the "Save failed" toast
 *   with the error message (fallback `settings.error.saveFailed`). Never
 *   throws.
 *
 * Security notes: the residency lock is a client-side guard in front of the
 * backend's gating; it starts locked so a slow or failed load never offers
 * the Google/Microsoft switches of a residency org. The settings store no
 * longer owns any of this. `@/api/settings` is mocked; nothing touches the
 * network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  disconnectOAuth,
  getMySettings,
  getOAuthAuthorizeUrl,
  getOAuthStatus,
  getOrgSettings,
  patchMySettings,
  patchOrgSettings,
} from '@/api/settings';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { useOrgServicesStore } from '@/stores/orgServices';
import { useToastStore } from '@/stores/toasts';
import type { OrgSettingsResponse, ToolsSettings } from '@/api/types';

vi.mock('@/api/settings', () => ({
  getMySettings: vi.fn(),
  patchMySettings: vi.fn(),
  resetMySettings: vi.fn(),
  getOrgSettings: vi.fn(),
  patchOrgSettings: vi.fn(),
  getOAuthStatus: vi.fn(),
  getOAuthAuthorizeUrl: vi.fn(),
  disconnectOAuth: vi.fn(),
}));

const mockedGetMySettings = vi.mocked(getMySettings);
const mockedPatchMySettings = vi.mocked(patchMySettings);
const mockedGetOrgSettings = vi.mocked(getOrgSettings);
const mockedPatchOrgSettings = vi.mocked(patchOrgSettings);
const mockedGetOAuthStatus = vi.mocked(getOAuthStatus);
const mockedGetOAuthAuthorizeUrl = vi.mocked(getOAuthAuthorizeUrl);
const mockedDisconnectOAuth = vi.mocked(disconnectOAuth);

const BLOCKED_TOOLS: ReadonlyArray<keyof ToolsSettings> = [
  'gmail',
  'google_calendar',
  'google_drive',
  'outlook',
  'outlook_calendar',
  'onedrive',
];

const TOOL_NAMES: ReadonlyArray<keyof ToolsSettings> = [...BLOCKED_TOOLS, 'memory'];

// --- Fixtures -------------------------------------------------------------

function tools(overrides: Partial<ToolsSettings> = {}): ToolsSettings {
  return {
    gmail: true,
    google_calendar: true,
    google_drive: true,
    outlook: true,
    outlook_calendar: true,
    onedrive: true,
    memory: true,
    ...overrides,
  };
}

function orgSettings(dataResidency: boolean, overrides: Partial<ToolsSettings> = {}): OrgSettingsResponse {
  return { tools: tools(overrides), data_residency: dataResidency };
}

type Catalog = Record<string, unknown>;

/** The catalog's own non-blank string for `key`; throws when the catalog lacks it. */
function text(catalog: Catalog, key: string): string {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`the catalog has no text for ${key}`);
  }
  return value;
}

const EN: Catalog = en;
const FR: Catalog = fr;

/** A promise the test settles by hand. Its rejection is never "unhandled". */
function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

/** 'resolved' when `promise` fulfils, else what it rejected with. */
function outcomeOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => 'resolved',
    (e: unknown) => e,
  );
}

function toastSummary(): Array<{ kind: string; title: string; body?: string }> {
  return useToastStore().toasts.map(({ kind, title, body }) => (body === undefined ? { kind, title } : { kind, title, body }));
}

/** A store loaded from `response`, with the org-settings mock call logs cleared. */
async function loadedStore(response: OrgSettingsResponse): Promise<ReturnType<typeof useOrgServicesStore>> {
  mockedGetOrgSettings.mockResolvedValueOnce(response);
  const store = useOrgServicesStore();
  await store.load();
  mockedGetOrgSettings.mockClear();
  return store;
}

/** Calls to any API other than the org settings. */
function otherRequests(): number {
  return (
    mockedGetMySettings.mock.calls.length +
    mockedPatchMySettings.mock.calls.length +
    mockedGetOAuthStatus.mock.calls.length +
    mockedGetOAuthAuthorizeUrl.mock.calls.length +
    mockedDisconnectOAuth.mock.calls.length
  );
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  mockedGetMySettings.mockReset();
  mockedPatchMySettings.mockReset();
  mockedGetOrgSettings.mockReset();
  mockedPatchOrgSettings.mockReset();
  mockedGetOAuthStatus.mockReset();
  mockedGetOAuthAuthorizeUrl.mockReset();
  mockedDisconnectOAuth.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('orgServicesStore initial state', () => {
  it('is the "orgServices" store: every tool on, residency assumed on (fail closed), not loaded', () => {
    const store = useOrgServicesStore();

    expect({ id: store.$id, tools: store.tools, dataResidency: store.dataResidency, loaded: store.loaded }).toEqual({
      id: 'orgServices',
      tools: tools(),
      dataResidency: true,
      loaded: false,
    });
  });

  // Regression guard moved from the settings store (issue #143: the local files tool is gone).
  it('default tools cover exactly the seven tool services, with no files key', () => {
    expect(Object.keys(useOrgServicesStore().tools).sort()).toEqual([...TOOL_NAMES].sort());
  });

  it('asks nothing of the server until load() is called', () => {
    useOrgServicesStore();

    expect(mockedGetOrgSettings.mock.calls.length + mockedPatchOrgSettings.mock.calls.length + otherRequests()).toBe(0);
  });
});

// --- load: GET /api/org/settings --------------------------------------------

describe('orgServicesStore load', () => {
  it('applies the org tools and the residency flag and marks the store loaded', async () => {
    mockedGetOrgSettings.mockResolvedValueOnce(orgSettings(false, { gmail: false, onedrive: false }));
    const store = useOrgServicesStore();

    const outcome = await outcomeOf(store.load());

    expect({
      outcome,
      requests: mockedGetOrgSettings.mock.calls.length,
      patches: mockedPatchOrgSettings.mock.calls.length,
      otherRequests: otherRequests(),
      tools: store.tools,
      dataResidency: store.dataResidency,
      loaded: store.loaded,
    }).toEqual({
      outcome: 'resolved',
      requests: 1,
      patches: 0,
      otherRequests: 0,
      tools: tools({ gmail: false, onedrive: false }),
      dataResidency: false,
      loaded: true,
    });
  });

  it('applies a residency org\'s flag and stored switches', async () => {
    mockedGetOrgSettings.mockResolvedValueOnce(orgSettings(true, { outlook: false, memory: false }));
    const store = useOrgServicesStore();

    await store.load();

    expect({ tools: store.tools, dataResidency: store.dataResidency, loaded: store.loaded }).toEqual({
      tools: tools({ outlook: false, memory: false }),
      dataResidency: true,
      loaded: true,
    });
  });

  it('keeps the fail-closed defaults, stays not loaded and never throws when the first load fails', async () => {
    mockedGetOrgSettings.mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Forbidden'));
    const store = useOrgServicesStore();

    const outcome = await outcomeOf(store.load());

    expect({ outcome, tools: store.tools, dataResidency: store.dataResidency, loaded: store.loaded }).toEqual({
      outcome: 'resolved',
      tools: tools(),
      dataResidency: true,
      loaded: false,
    });
  });

  it('keeps the loaded tools and residency flag when a later load fails', async () => {
    const store = await loadedStore(orgSettings(false, { outlook: false }));
    mockedGetOrgSettings.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const outcome = await outcomeOf(store.load());

    expect({ outcome, tools: store.tools, dataResidency: store.dataResidency }).toEqual({
      outcome: 'resolved',
      tools: tools({ outlook: false }),
      dataResidency: false,
    });
  });

  it('replaces a previously loaded state on a successful reload', async () => {
    const store = await loadedStore(orgSettings(false, { gmail: false }));
    mockedGetOrgSettings.mockResolvedValueOnce(orgSettings(true, { memory: false }));

    await store.load();

    expect({ tools: store.tools, dataResidency: store.dataResidency }).toEqual({
      tools: tools({ memory: false }),
      dataResidency: true,
    });
  });

  it('shows no toast, whether the load succeeds or fails', async () => {
    mockedGetOrgSettings
      .mockResolvedValueOnce(orgSettings(false))
      .mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    const store = useOrgServicesStore();

    await store.load();
    await store.load();

    expect(toastSummary()).toEqual([]);
  });
});

// --- isLocked -------------------------------------------------------------

describe('orgServicesStore isLocked', () => {
  it('locks the six Google/Microsoft tools but not memory before anything is loaded (fail closed)', () => {
    const store = useOrgServicesStore();

    expect(TOOL_NAMES.filter((tool) => store.isLocked(tool))).toEqual([...BLOCKED_TOOLS]);
  });

  it('locks nothing once the org is loaded without residency', async () => {
    const store = await loadedStore(orgSettings(false));

    expect(TOOL_NAMES.filter((tool) => store.isLocked(tool))).toEqual([]);
  });

  it('locks the six Google/Microsoft tools but not memory for a residency org', async () => {
    const store = await loadedStore(orgSettings(true));

    expect(TOOL_NAMES.filter((tool) => store.isLocked(tool))).toEqual([...BLOCKED_TOOLS]);
  });

  it('follows the residency flag a save returns', async () => {
    const store = await loadedStore(orgSettings(false));
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(true, { memory: false }));

    await store.setEnabled('memory', false);

    expect(TOOL_NAMES.filter((tool) => store.isLocked(tool))).toEqual([...BLOCKED_TOOLS]);
  });
});

// --- setEnabled: PATCH /api/org/settings ------------------------------------

describe('orgServicesStore setEnabled', () => {
  it.each(BLOCKED_TOOLS)(
    'makes no API call and changes nothing for the locked %s before the org is loaded',
    async (tool) => {
      const store = useOrgServicesStore();

      const outcome = await outcomeOf(store.setEnabled(tool, false));

      expect({ outcome, patches: mockedPatchOrgSettings.mock.calls.length, tools: store.tools }).toEqual({
        outcome: 'resolved',
        patches: 0,
        tools: tools(),
      });
    },
  );

  it.each(BLOCKED_TOOLS)('makes no API call and changes nothing for %s in a residency org', async (tool) => {
    const store = await loadedStore(orgSettings(true, { [tool]: false }));

    const outcome = await outcomeOf(store.setEnabled(tool, true));

    expect({ outcome, patches: mockedPatchOrgSettings.mock.calls.length, tools: store.tools }).toEqual({
      outcome: 'resolved',
      patches: 0,
      tools: tools({ [tool]: false }),
    });
  });

  it('still saves memory in a residency org', async () => {
    const store = await loadedStore(orgSettings(true));
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(true, { memory: false }));

    await store.setEnabled('memory', false);

    expect({ patches: mockedPatchOrgSettings.mock.calls, tools: store.tools }).toStrictEqual({
      patches: [[{ tools: { memory: false } }]],
      tools: tools({ memory: false }),
    });
  });

  it.each(TOOL_NAMES)(
    'switches %s optimistically and sends only that tool to PATCH /api/org/settings',
    async (tool) => {
      const store = await loadedStore(orgSettings(false));
      const pending = deferred<OrgSettingsResponse>();
      mockedPatchOrgSettings.mockReturnValueOnce(pending.promise);

      const done = outcomeOf(store.setEnabled(tool, false));
      const during = { ...store.tools };
      pending.resolve(orgSettings(false, { [tool]: false }));
      const outcome = await done;

      expect({
        outcome,
        during,
        orgPatches: mockedPatchOrgSettings.mock.calls,
        otherRequests: otherRequests(),
      }).toStrictEqual({
        outcome: 'resolved',
        during: tools({ [tool]: false }),
        orgPatches: [[{ tools: { [tool]: false } }]],
        otherRequests: 0,
      });
    },
  );

  it('switches a loaded "off" tool back on optimistically', async () => {
    const store = await loadedStore(orgSettings(false, { outlook_calendar: false }));
    const pending = deferred<OrgSettingsResponse>();
    mockedPatchOrgSettings.mockReturnValueOnce(pending.promise);

    const done = outcomeOf(store.setEnabled('outlook_calendar', true));
    const during = store.tools.outlook_calendar;
    pending.resolve(orgSettings(false));
    await done;

    expect({ during, patches: mockedPatchOrgSettings.mock.calls, after: store.tools }).toStrictEqual({
      during: true,
      patches: [[{ tools: { outlook_calendar: true } }]],
      after: tools(),
    });
  });

  it('applies the tools the server returns', async () => {
    // Another admin switched Outlook off meanwhile: the response is the stored truth.
    const store = await loadedStore(orgSettings(false));
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(false, { gmail: false, outlook: false }));

    await store.setEnabled('gmail', false);

    expect(store.tools).toEqual(tools({ gmail: false, outlook: false }));
  });

  it('applies the residency flag the server returns', async () => {
    const store = await loadedStore(orgSettings(false));
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(true, { google_drive: false }));

    await store.setEnabled('google_drive', false);

    expect({ tools: store.tools, dataResidency: store.dataResidency }).toEqual({
      tools: tools({ google_drive: false }),
      dataResidency: true,
    });
  });

  it('adds the translated "Saved" success toast', async () => {
    const store = await loadedStore(orgSettings(false));
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(false, { onedrive: false }));

    await store.setEnabled('onedrive', false);

    expect(toastSummary()).toEqual([{ kind: 'success', title: text(EN, 'toast.common.saved') }]);
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    const store = await loadedStore(orgSettings(false));
    setLocale('fr');
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings(false, { memory: false }));

    await store.setEnabled('memory', false);

    expect(toastSummary()).toEqual([{ kind: 'success', title: text(FR, 'toast.common.saved') }]);
  });

  it('reverts the tool, shows the "Save failed" toast with the message and never throws when the save fails', async () => {
    const store = await loadedStore(orgSettings(false));
    mockedPatchOrgSettings.mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Forbidden'));

    const outcome = await outcomeOf(store.setEnabled('outlook', false));

    expect({
      outcome,
      tools: store.tools,
      dataResidency: store.dataResidency,
      toasts: toastSummary(),
      orgPatches: mockedPatchOrgSettings.mock.calls,
    }).toEqual({
      outcome: 'resolved',
      tools: tools(),
      dataResidency: false,
      toasts: [{ kind: 'error', title: text(EN, 'toast.common.saveFailed.title'), body: 'Forbidden' }],
      orgPatches: [[{ tools: { outlook: false } }]],
    });
  });

  it('reverts a loaded "off" tool when switching it on fails with a non-Error rejection', async () => {
    const store = await loadedStore(orgSettings(false, { gmail: false }));
    mockedPatchOrgSettings.mockRejectedValueOnce('offline');

    const outcome = await outcomeOf(store.setEnabled('gmail', true));

    expect({ outcome, tools: store.tools, toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      tools: tools({ gmail: false }),
      toasts: [
        {
          kind: 'error',
          title: text(EN, 'toast.common.saveFailed.title'),
          body: text(EN, 'settings.error.saveFailed'),
        },
      ],
    });
  });

  it('takes the failure toast title and fallback body from the active locale', async () => {
    const store = await loadedStore(orgSettings(false));
    setLocale('fr');
    mockedPatchOrgSettings.mockRejectedValueOnce({ detail: 'not an Error' });

    await outcomeOf(store.setEnabled('memory', false));

    expect(toastSummary()).toEqual([
      { kind: 'error', title: text(FR, 'toast.common.saveFailed.title'), body: text(FR, 'settings.error.saveFailed') },
    ]);
  });

  it('reverts only the failed tool while another switch is still saving', async () => {
    const store = await loadedStore(orgSettings(false));
    const gmailSave = deferred<OrgSettingsResponse>();
    const memorySave = deferred<OrgSettingsResponse>();
    mockedPatchOrgSettings.mockReturnValueOnce(gmailSave.promise).mockReturnValueOnce(memorySave.promise);

    const gmailDone = outcomeOf(store.setEnabled('gmail', false));
    const memoryDone = outcomeOf(store.setEnabled('memory', false));
    gmailSave.reject(new ApiError(500, 'Internal Server Error'));
    const gmailOutcome = await gmailDone;
    const afterFailure = { ...store.tools };
    memorySave.resolve(orgSettings(false, { memory: false }));
    await memoryDone;

    expect({ gmailOutcome, afterFailure, final: store.tools }).toEqual({
      gmailOutcome: 'resolved',
      afterFailure: tools({ memory: false }),
      final: tools({ memory: false }),
    });
  });
});
