/**
 * Settings store tests (issue #159: settings split into platform,
 * organization and user scopes).
 *
 * The Settings page now shows only the caller's own settings, and the LLM
 * (Agent) section is gone, so the store keeps no LLM state or actions. What
 * it does keep:
 * - `loadSettings()` / `saveSetting(patch)`: the user's theme and
 *   notifications through `GET` / `PATCH /api/me/settings` (loading and error
 *   state, success and error toasts, the error rethrown by `saveSetting`).
 * - `setNotificationsEnabled(v)`: optimistic, reverted when the save fails,
 *   never throws.
 * - `sessionId` / `newSession()`: unchanged (the chat store depends on them).
 * Toast copy and fallback messages come from the i18n catalogs.
 *
 * Issue #162 (the Tools page becomes "my connections"; the Org Admin's
 * service switches move to the Organization console): the connection and
 * org-tool parts left this store. It no longer exposes `connectedAccounts`,
 * `loadConnections`, `connectGoogle`, `connectMicrosoft`, `disconnectGoogle`,
 * `disconnectMicrosoft`, `tools`, `loadOrgTools` or `setToolEnabled`. Their
 * tests moved to `stores/connections.test.ts` (`useConnectionsStore`) and
 * `stores/orgServices.test.ts` (`useOrgServicesStore`).
 *
 * Issue #35 (Settings controls: task-done pings, reset my settings):
 * - `taskDoneNotifications` starts `false` (off by default) and every applied
 *   user-settings response (`loadSettings`, `saveSetting`) sets it from
 *   `notifications.task_done`, independently of `notificationsEnabled`.
 * - `setTaskDoneNotifications(v)`: optimistic, sends ONLY
 *   `{ notifications: { task_done: v } }`, toasts "Saved" on success, reverts
 *   and toasts "Save failed" on failure, never throws.
 * - `resetSettings()`: one `POST /api/me/settings/reset` (`resetMySettings`),
 *   applies the returned theme / notifications / task-done flag and toasts
 *   `toast.settings.settingsReset`. On failure it toasts
 *   `toast.settings.resetFailed.title` with the error message (fallback
 *   `settings.error.resetFailed`), keeps the state and never throws. It never
 *   disconnects an account, reads or patches the org settings, patches the
 *   user settings, or asks for the OAuth status, and leaves the session id
 *   alone.
 *
 * Issue #149 guards stay: no bearer-token state and no read of the old
 * `admino_auth_token` localStorage key.
 *
 * The network layer (`@/api/settings`) is mocked; nothing touches `fetch`.
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
  resetMySettings,
} from '@/api/settings';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { useSettingsStore } from '@/stores/settings';
import { useToastStore } from '@/stores/toasts';
import type { AppTheme, UserSettingsResponse } from '@/api/types';

vi.mock('@/api/settings', () => ({
  getMySettings: vi.fn(),
  patchMySettings: vi.fn(),
  getOrgSettings: vi.fn(),
  patchOrgSettings: vi.fn(),
  getOAuthStatus: vi.fn(),
  getOAuthAuthorizeUrl: vi.fn(),
  disconnectOAuth: vi.fn(),
  resetMySettings: vi.fn(),
}));

const mockedGetMySettings = vi.mocked(getMySettings);
const mockedPatchMySettings = vi.mocked(patchMySettings);
const mockedGetOrgSettings = vi.mocked(getOrgSettings);
const mockedPatchOrgSettings = vi.mocked(patchOrgSettings);
const mockedGetOAuthStatus = vi.mocked(getOAuthStatus);
const mockedGetOAuthAuthorizeUrl = vi.mocked(getOAuthAuthorizeUrl);
const mockedDisconnectOAuth = vi.mocked(disconnectOAuth);
const mockedResetMySettings = vi.mocked(resetMySettings);

/** localStorage key the store persists the session id under. */
const SESSION_STORAGE_KEY = 'admino_session_id';
/** Shape the backend accepts for a session id. */
const SESSION_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

/** State and actions of the removed Settings → Agent section. */
const REMOVED_LLM_KEYS = [
  'provider',
  'llmProvider',
  'llmAnthropicModel',
  'llmOpenAiModel',
  'llmVllmModel',
  'llmInfomaniakModel',
  'vllmAvailableModels',
  'infomaniakAvailableModels',
  'anthropicKeyConfigured',
  'openAiKeyConfigured',
  'infomaniakTokenConfigured',
  'setProvider',
  'setAnthropicModel',
  'setOpenAiModel',
  'setVllmModel',
  'setInfomaniakModel',
];

/** Connection and org-tool state and actions that moved out (issue #162). */
const REMOVED_CONNECTION_KEYS = [
  'connectedAccounts',
  'loadConnections',
  'connectGoogle',
  'connectMicrosoft',
  'disconnectGoogle',
  'disconnectMicrosoft',
  'tools',
  'loadOrgTools',
  'setToolEnabled',
];

// --- Fixtures -------------------------------------------------------------

function mySettings(theme: AppTheme, enabled: boolean, taskDone = false): UserSettingsResponse {
  return { appearance: { theme }, notifications: { enabled, task_done: taskDone } };
}

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

function toastKinds(): string[] {
  return useToastStore().toasts.map((toast) => toast.kind);
}

/**
 * A stand-in localStorage that records every key read. happy-dom's Storage
 * can't be spied through Storage.prototype, so the global is replaced.
 */
function recordingStorage(initial: Record<string, string>): { storage: Storage; reads: string[] } {
  const data = new Map(Object.entries(initial));
  const reads: string[] = [];
  const storage: Storage = {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key: string) => {
      reads.push(key);
      return data.get(key) ?? null;
    },
    key: (index: number) => [...data.keys()][index] ?? null,
    removeItem: (key: string) => {
      data.delete(key);
    },
    setItem: (key: string, value: string) => {
      data.set(key, String(value));
    },
  };
  return { storage, reads };
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
  mockedResetMySettings.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('settingsStore initial state', () => {
  it('starts on light, notifications on, not loading and without an error', () => {
    const store = useSettingsStore();

    expect({
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
      loading: store.loading,
      error: store.error,
    }).toEqual({
      theme: 'light',
      notificationsEnabled: true,
      loading: false,
      error: null,
    });
  });
});

// --- Connections and org tools left Settings (issue #162) -----------------

describe('settingsStore exposes no connection or org-tool state (issue #162)', () => {
  it.each(REMOVED_CONNECTION_KEYS)('exposes no %s', (key) => {
    expect(key in useSettingsStore()).toBe(false);
  });

  it('keeps no connection or org-tool key at all in its returned API', () => {
    const store = useSettingsStore();

    expect(REMOVED_CONNECTION_KEYS.filter((key) => key in store || key in store.$state)).toEqual([]);
  });

  it('keeps the session id, theme, notifications and reset API', () => {
    const store = useSettingsStore();
    const kept = [
      'sessionId',
      'newSession',
      'theme',
      'notificationsEnabled',
      'taskDoneNotifications',
      'loading',
      'error',
      'loadSettings',
      'saveSetting',
      'setNotificationsEnabled',
      'setTaskDoneNotifications',
      'resetSettings',
    ];

    expect(kept.filter((key) => !(key in store))).toEqual([]);
  });
});

// --- The LLM (Agent) section left Settings --------------------------------

describe('settingsStore exposes no LLM state (issue #159)', () => {
  it.each(REMOVED_LLM_KEYS)('exposes no %s', (key) => {
    expect(key in useSettingsStore()).toBe(false);
  });
});

// --- loadSettings: GET /api/me/settings -----------------------------------

describe('settingsStore loadSettings', () => {
  it('is loading while GET /api/me/settings is pending, and not after', async () => {
    const pending = deferred<UserSettingsResponse>();
    mockedGetMySettings.mockReturnValueOnce(pending.promise);
    const store = useSettingsStore();

    const done = store.loadSettings();
    const during = { loading: store.loading, requests: mockedGetMySettings.mock.calls.length };
    pending.resolve(mySettings('dark', false));
    await done;

    expect({ during, after: store.loading }).toEqual({
      during: { loading: true, requests: 1 },
      after: false,
    });
  });

  it('applies the theme and notifications and asks nothing of the org scope', async () => {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('dark', false));
    const store = useSettingsStore();

    await store.loadSettings();

    expect({
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
      error: store.error,
      orgRequests: mockedGetOrgSettings.mock.calls.length + mockedPatchOrgSettings.mock.calls.length,
    }).toEqual({ theme: 'dark', notificationsEnabled: false, error: null, orgRequests: 0 });
  });

  it('replaces a previously loaded theme and notifications', async () => {
    mockedGetMySettings
      .mockResolvedValueOnce(mySettings('dark', false))
      .mockResolvedValueOnce(mySettings('system', true));
    const store = useSettingsStore();

    await store.loadSettings();
    await store.loadSettings();

    expect({ theme: store.theme, notificationsEnabled: store.notificationsEnabled }).toEqual({
      theme: 'system',
      notificationsEnabled: true,
    });
  });

  it('sets error to the error message, stops loading and never throws', async () => {
    mockedGetMySettings.mockRejectedValueOnce(new ApiError(503, 'Service Unavailable', 'Service unavailable'));
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.loadSettings());

    expect({ outcome, error: store.error, loading: store.loading }).toEqual({
      outcome: 'resolved',
      error: 'Service unavailable',
      loading: false,
    });
  });

  it('keeps the current theme and notifications when loading fails', async () => {
    mockedGetMySettings
      .mockResolvedValueOnce(mySettings('dark', false))
      .mockRejectedValueOnce(new Error('Service unavailable'));
    const store = useSettingsStore();

    await store.loadSettings();
    await store.loadSettings();

    expect({ theme: store.theme, notificationsEnabled: store.notificationsEnabled }).toEqual({
      theme: 'dark',
      notificationsEnabled: false,
    });
  });

  it('falls back to the translated load-failed message for a non-Error rejection', async () => {
    mockedGetMySettings.mockRejectedValueOnce('offline');
    const store = useSettingsStore();

    await store.loadSettings();

    expect(store.error).toBe(en['settings.error.loadFailed']);
  });

  it('takes the load-failed fallback from the active locale', async () => {
    setLocale('fr');
    mockedGetMySettings.mockRejectedValueOnce({ detail: 'not an Error' });
    const store = useSettingsStore();

    await store.loadSettings();

    expect(store.error).toBe(fr['settings.error.loadFailed']);
  });

  it('clears a previous error on a successful reload', async () => {
    mockedGetMySettings
      .mockRejectedValueOnce(new Error('Service unavailable'))
      .mockResolvedValueOnce(mySettings('light', true));
    const store = useSettingsStore();

    await store.loadSettings();
    const failed = store.error;
    await store.loadSettings();

    expect({ failed, error: store.error }).toEqual({ failed: 'Service unavailable', error: null });
  });
});

// --- saveSetting: PATCH /api/me/settings ----------------------------------

describe('settingsStore saveSetting', () => {
  it('sends exactly the patch to PATCH /api/me/settings and applies the stored result', async () => {
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('dark', false));
    const store = useSettingsStore();

    await store.saveSetting({ appearance: { theme: 'dark' } });

    expect({
      patches: mockedPatchMySettings.mock.calls,
      orgPatches: mockedPatchOrgSettings.mock.calls.length,
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
    }).toEqual({
      patches: [[{ appearance: { theme: 'dark' } }]],
      orgPatches: 0,
      theme: 'dark',
      notificationsEnabled: false,
    });
  });

  it('adds the translated "Saved" success toast', async () => {
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('light', false));

    await useSettingsStore().saveSetting({ notifications: { enabled: false } });

    expect(toastSummary()).toEqual([{ kind: 'success', title: en['toast.common.saved'] }]);
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    setLocale('fr');
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('light', true));

    await useSettingsStore().saveSetting({ notifications: { enabled: true } });

    expect(toastSummary()).toEqual([{ kind: 'success', title: fr['toast.common.saved'] }]);
  });

  it('on failure adds a "Save failed" toast with the error message, rethrows and keeps the state', async () => {
    const rejection = new ApiError(422, 'Unprocessable Entity', 'Nothing to update');
    mockedPatchMySettings.mockRejectedValueOnce(rejection);
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.saveSetting({ appearance: { theme: 'dark' } }));

    expect({
      rethrown: outcome === rejection,
      toasts: toastSummary(),
      theme: store.theme,
    }).toEqual({
      rethrown: true,
      toasts: [{ kind: 'error', title: en['toast.common.saveFailed.title'], body: 'Nothing to update' }],
      theme: 'light',
    });
  });

  it('falls back to the translated save-failed body for a non-Error rejection and rethrows it', async () => {
    mockedPatchMySettings.mockRejectedValueOnce('offline');
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.saveSetting({ notifications: { enabled: false } }));

    expect({ outcome, toasts: toastSummary() }).toEqual({
      outcome: 'offline',
      toasts: [
        { kind: 'error', title: en['toast.common.saveFailed.title'], body: en['settings.error.saveFailed'] },
      ],
    });
  });
});

// --- setNotificationsEnabled ----------------------------------------------

describe('settingsStore setNotificationsEnabled', () => {
  it('switches optimistically, then sends { notifications: { enabled } } and applies the result', async () => {
    const pending = deferred<UserSettingsResponse>();
    mockedPatchMySettings.mockReturnValueOnce(pending.promise);
    const store = useSettingsStore();

    const done = outcomeOf(store.setNotificationsEnabled(false));
    const during = store.notificationsEnabled;
    pending.resolve(mySettings('light', false));
    const outcome = await done;

    expect({
      during,
      patches: mockedPatchMySettings.mock.calls,
      outcome,
      after: store.notificationsEnabled,
    }).toEqual({
      during: false,
      patches: [[{ notifications: { enabled: false } }]],
      outcome: 'resolved',
      after: false,
    });
  });

  it('reverts to the default (on), shows an error toast and never throws when the save fails', async () => {
    mockedPatchMySettings.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.setNotificationsEnabled(false));

    expect({ outcome, enabled: store.notificationsEnabled, toasts: toastKinds() }).toEqual({
      outcome: 'resolved',
      enabled: true,
      toasts: ['error'],
    });
  });

  it('reverts to a loaded "off" when switching on fails', async () => {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('light', false));
    mockedPatchMySettings.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    const store = useSettingsStore();
    await store.loadSettings();

    const outcome = await outcomeOf(store.setNotificationsEnabled(true));

    expect({
      outcome,
      enabled: store.notificationsEnabled,
      patches: mockedPatchMySettings.mock.calls,
    }).toEqual({
      outcome: 'resolved',
      enabled: false,
      patches: [[{ notifications: { enabled: true } }]],
    });
  });
});

// --- Task-done pings (issue #35) -------------------------------------------

describe('settingsStore taskDoneNotifications state', () => {
  it('starts off (false)', () => {
    expect(useSettingsStore().taskDoneNotifications).toBe(false);
  });

  it('exports setTaskDoneNotifications and resetSettings as actions', () => {
    const store = useSettingsStore();

    expect([typeof store.setTaskDoneNotifications, typeof store.resetSettings]).toEqual(['function', 'function']);
  });

  it.each([
    [true, true],
    [true, false],
    [false, true],
    [false, false],
  ])(
    'loadSettings applies enabled=%s and task_done=%s independently',
    async (enabled, taskDone) => {
      mockedGetMySettings.mockResolvedValueOnce(mySettings('dark', enabled, taskDone));
      const store = useSettingsStore();

      await store.loadSettings();

      expect({
        notificationsEnabled: store.notificationsEnabled,
        taskDoneNotifications: store.taskDoneNotifications,
      }).toEqual({ notificationsEnabled: enabled, taskDoneNotifications: taskDone });
    },
  );

  it('loadSettings replaces a previously loaded task-done flag', async () => {
    mockedGetMySettings
      .mockResolvedValueOnce(mySettings('light', true, true))
      .mockResolvedValueOnce(mySettings('light', true, false));
    const store = useSettingsStore();

    await store.loadSettings();
    const first = store.taskDoneNotifications;
    await store.loadSettings();

    expect({ first, second: store.taskDoneNotifications }).toEqual({ first: true, second: false });
  });

  it('keeps a loaded task-done flag when a later load fails', async () => {
    mockedGetMySettings
      .mockResolvedValueOnce(mySettings('light', true, true))
      .mockRejectedValueOnce(new Error('Service unavailable'));
    const store = useSettingsStore();

    await store.loadSettings();
    await store.loadSettings();

    expect(store.taskDoneNotifications).toBe(true);
  });

  it('saveSetting applies the task-done flag of the stored result', async () => {
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('dark', true, true));
    const store = useSettingsStore();

    await store.saveSetting({ appearance: { theme: 'dark' } });

    expect(store.taskDoneNotifications).toBe(true);
  });
});

describe('settingsStore setTaskDoneNotifications', () => {
  it('switches on optimistically, sends only { notifications: { task_done: true } } and applies the result', async () => {
    const pending = deferred<UserSettingsResponse>();
    mockedPatchMySettings.mockReturnValueOnce(pending.promise);
    const store = useSettingsStore();

    const done = outcomeOf(store.setTaskDoneNotifications(true));
    const during = store.taskDoneNotifications;
    pending.resolve(mySettings('light', true, true));
    const outcome = await done;

    expect({
      during,
      patches: mockedPatchMySettings.mock.calls,
      outcome,
      after: store.taskDoneNotifications,
    }).toStrictEqual({
      during: true,
      patches: [[{ notifications: { task_done: true } }]],
      outcome: 'resolved',
      after: true,
    });
  });

  it('switches a loaded "on" off optimistically and sends only { notifications: { task_done: false } }', async () => {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('light', true, true));
    const pending = deferred<UserSettingsResponse>();
    mockedPatchMySettings.mockReturnValueOnce(pending.promise);
    const store = useSettingsStore();
    await store.loadSettings();

    const done = outcomeOf(store.setTaskDoneNotifications(false));
    const during = store.taskDoneNotifications;
    pending.resolve(mySettings('light', true, false));
    await done;

    expect({ during, patches: mockedPatchMySettings.mock.calls, after: store.taskDoneNotifications }).toStrictEqual({
      during: false,
      patches: [[{ notifications: { task_done: false } }]],
      after: false,
    });
  });

  it('flips only the task-done flag while the save is pending (theme and tool-approval pings stay)', async () => {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('dark', false, false));
    const pending = deferred<UserSettingsResponse>();
    mockedPatchMySettings.mockReturnValueOnce(pending.promise);
    const store = useSettingsStore();
    await store.loadSettings();

    const done = outcomeOf(store.setTaskDoneNotifications(true));
    const during = {
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
      taskDoneNotifications: store.taskDoneNotifications,
    };
    pending.resolve(mySettings('dark', false, true));
    await done;

    expect(during).toEqual({ theme: 'dark', notificationsEnabled: false, taskDoneNotifications: true });
  });

  it('adds the translated "Saved" success toast', async () => {
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('light', true, true));

    await useSettingsStore().setTaskDoneNotifications(true);

    expect(toastSummary()).toEqual([{ kind: 'success', title: en['toast.common.saved'] }]);
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    setLocale('fr');
    mockedPatchMySettings.mockResolvedValueOnce(mySettings('light', true, true));

    await useSettingsStore().setTaskDoneNotifications(true);

    expect(toastSummary()).toEqual([{ kind: 'success', title: fr['toast.common.saved'] }]);
  });

  it('reverts to the default (off), shows a "Save failed" toast and never throws when the save fails', async () => {
    mockedPatchMySettings.mockRejectedValueOnce(new ApiError(429, 'Too Many Requests', 'Rate limit exceeded'));
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.setTaskDoneNotifications(true));

    expect({ outcome, taskDone: store.taskDoneNotifications, toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      taskDone: false,
      toasts: [{ kind: 'error', title: en['toast.common.saveFailed.title'], body: 'Rate limit exceeded' }],
    });
  });

  it('reverts to a loaded "on" when switching off fails with a non-Error rejection', async () => {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('light', true, true));
    mockedPatchMySettings.mockRejectedValueOnce('offline');
    const store = useSettingsStore();
    await store.loadSettings();

    const outcome = await outcomeOf(store.setTaskDoneNotifications(false));

    expect({
      outcome,
      taskDone: store.taskDoneNotifications,
      patches: mockedPatchMySettings.mock.calls,
      toasts: toastSummary(),
    }).toStrictEqual({
      outcome: 'resolved',
      taskDone: true,
      patches: [[{ notifications: { task_done: false } }]],
      toasts: [{ kind: 'error', title: en['toast.common.saveFailed.title'], body: en['settings.error.saveFailed'] }],
    });
  });
});

// --- Reset my settings: POST /api/me/settings/reset (issue #35) ------------

describe('settingsStore resetSettings', () => {
  /** Loads non-default user settings: dark, tool-approval pings off, task-done pings on. */
  async function loadCustomized(store: ReturnType<typeof useSettingsStore>): Promise<void> {
    mockedGetMySettings.mockResolvedValueOnce(mySettings('dark', false, true));
    await store.loadSettings();
  }

  function userState(store: ReturnType<typeof useSettingsStore>) {
    return {
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
      taskDoneNotifications: store.taskDoneNotifications,
    };
  }

  it('calls resetMySettings once, with no arguments', async () => {
    mockedResetMySettings.mockResolvedValueOnce(mySettings('light', true, false));
    const store = useSettingsStore();

    await store.resetSettings();

    expect(mockedResetMySettings.mock.calls).toEqual([[]]);
  });

  it('applies the returned defaults over customized settings and adds the "settings reset" toast', async () => {
    const store = useSettingsStore();
    await loadCustomized(store);
    mockedResetMySettings.mockResolvedValueOnce(mySettings('light', true, false));

    const outcome = await outcomeOf(store.resetSettings());

    expect({ outcome, state: userState(store), toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      state: { theme: 'light', notificationsEnabled: true, taskDoneNotifications: false },
      toasts: [{ kind: 'success', title: en['toast.settings.settingsReset'] }],
    });
  });

  it('applies exactly what the server returns, not hard-coded defaults', async () => {
    const store = useSettingsStore();
    mockedResetMySettings.mockResolvedValueOnce(mySettings('system', false, true));

    await store.resetSettings();

    expect(userState(store)).toEqual({ theme: 'system', notificationsEnabled: false, taskDoneNotifications: true });
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    setLocale('fr');
    mockedResetMySettings.mockResolvedValueOnce(mySettings('light', true, false));

    await useSettingsStore().resetSettings();

    expect(toastSummary()).toEqual([{ kind: 'success', title: fr['toast.settings.settingsReset'] }]);
  });

  it.each([
    ['429 rate limit', new ApiError(429, 'Too Many Requests', 'Rate limit exceeded'), 'Rate limit exceeded'],
    ['403', new ApiError(403, 'Forbidden', 'Forbidden'), 'Forbidden'],
    ['network failure', new TypeError('Failed to fetch'), 'Failed to fetch'],
  ])(
    'on a %s shows a "Reset failed" toast with the error message, keeps the settings and never throws',
    async (_label, rejection, body) => {
      const store = useSettingsStore();
      await loadCustomized(store);
      mockedResetMySettings.mockRejectedValueOnce(rejection);

      const outcome = await outcomeOf(store.resetSettings());

      expect({ outcome, state: userState(store), toasts: toastSummary() }).toEqual({
        outcome: 'resolved',
        state: { theme: 'dark', notificationsEnabled: false, taskDoneNotifications: true },
        toasts: [{ kind: 'error', title: en['toast.settings.resetFailed.title'], body }],
      });
    },
  );

  it('falls back to the translated reset-failed body for a non-Error rejection', async () => {
    mockedResetMySettings.mockRejectedValueOnce('offline');
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.resetSettings());

    expect({ outcome, state: userState(store), toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      state: { theme: 'light', notificationsEnabled: true, taskDoneNotifications: false },
      toasts: [
        { kind: 'error', title: en['toast.settings.resetFailed.title'], body: en['settings.error.resetFailed'] },
      ],
    });
  });

  it('takes the failure toast title and fallback body from the active locale', async () => {
    setLocale('fr');
    mockedResetMySettings.mockRejectedValueOnce({ detail: 'not an Error' });

    await outcomeOf(useSettingsStore().resetSettings());

    expect(toastSummary()).toEqual([
      { kind: 'error', title: fr['toast.settings.resetFailed.title'], body: fr['settings.error.resetFailed'] },
    ]);
  });

  it.each([
    ['succeeds', true],
    ['fails', false],
  ])(
    'when the reset %s it never disconnects, touches the org settings or asks for the OAuth status, and keeps the session',
    async (_label, succeeds) => {
      const store = useSettingsStore();
      const sessionBefore = store.sessionId;
      if (succeeds) {
        mockedResetMySettings.mockResolvedValueOnce(mySettings('light', true, false));
      } else {
        mockedResetMySettings.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
      }

      await outcomeOf(store.resetSettings());

      expect({
        resets: mockedResetMySettings.mock.calls.length,
        disconnects: mockedDisconnectOAuth.mock.calls.length,
        orgReads: mockedGetOrgSettings.mock.calls.length,
        orgPatches: mockedPatchOrgSettings.mock.calls.length,
        userPatches: mockedPatchMySettings.mock.calls.length,
        statusRequests: mockedGetOAuthStatus.mock.calls.length,
        authorizeRequests: mockedGetOAuthAuthorizeUrl.mock.calls.length,
        sessionId: store.sessionId,
        sessionStored: localStorage.getItem(SESSION_STORAGE_KEY),
      }).toEqual({
        resets: 1,
        disconnects: 0,
        orgReads: 0,
        orgPatches: 0,
        userPatches: 0,
        statusRequests: 0,
        authorizeRequests: 0,
        sessionId: sessionBefore,
        sessionStored: sessionBefore,
      });
    },
  );
});

// --- Session id (unchanged; regression guards) ----------------------------

describe('settingsStore session id', () => {
  it('keeps a valid session id already stored', () => {
    localStorage.setItem(SESSION_STORAGE_KEY, 's-kept_session-01');

    expect(useSettingsStore().sessionId).toBe('s-kept_session-01');
  });

  it('newSession rotates to a fresh valid id and persists it', () => {
    const store = useSettingsStore();
    const before = store.sessionId;

    store.newSession();

    expect({
      rotated: store.sessionId !== before,
      valid: SESSION_ID_RE.test(store.sessionId),
      persisted: localStorage.getItem(SESSION_STORAGE_KEY) === store.sessionId,
    }).toEqual({ rotated: true, valid: true, persisted: true });
  });
});

// --- No bearer token (issue #149; regression guards) ----------------------

describe('settingsStore has no bearer token', () => {
  it.each(['token', 'needsAuth', 'setToken', 'skipAuth'])('exposes no %s', (key) => {
    expect(key in useSettingsStore()).toBe(false);
  });

  it('never reads a legacy admino_auth_token left in localStorage', () => {
    const { storage, reads } = recordingStorage({
      admino_auth_token: 'legacy-bearer-token-0123456789-abcdef',
    });
    vi.stubGlobal('localStorage', storage);

    useSettingsStore();

    expect(reads).not.toContain('admino_auth_token');
  });
});
