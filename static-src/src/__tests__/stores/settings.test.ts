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
 * - `loadConnections()`: the Google and Microsoft connection status from
 *   `GET /api/oauth/{provider}/status`. A provider whose status fails reads as
 *   disconnected, a non-string email is stored as `null`, never throws.
 * - `loadOrgTools()` / `setToolEnabled(tool, enabled)`: the organization's
 *   enabled tool services through `GET` / `PATCH /api/org/settings` (Org Admin
 *   only). The toggle is optimistic; a failed save reverts only that tool,
 *   shows an error toast and never throws.
 * - `disconnectGoogle()` / `disconnectMicrosoft()`: disconnect, then refresh
 *   the connection status (no user-settings reload).
 * - `sessionId` / `newSession()`: unchanged (the chat store depends on them).
 * Toast copy and fallback messages come from the i18n catalogs.
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
 *   disconnects an account, patches the org or user settings, or asks for the
 *   OAuth status, and leaves the connected accounts, org tools and session id
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
import type {
  AppTheme,
  OAuthConnectionStatus,
  OrgSettingsResponse,
  ToolsSettings,
  UserSettingsResponse,
} from '@/api/types';

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

const TOOL_NAMES: ReadonlyArray<keyof ToolsSettings> = [
  'gmail',
  'google_calendar',
  'google_drive',
  'outlook',
  'outlook_calendar',
  'onedrive',
  'memory',
];

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

const DISCONNECTED: OAuthConnectionStatus = {
  connected: false,
  healthy: false,
  email: null,
  services: [],
};

const GOOGLE_CONNECTED: OAuthConnectionStatus = {
  connected: true,
  healthy: true,
  email: 'alice@example.ch',
  services: ['gmail', 'google_calendar', 'google_drive'],
};

const MICROSOFT_CONNECTED: OAuthConnectionStatus = {
  connected: true,
  healthy: false,
  email: 'alice@contoso.example',
  services: ['outlook'],
};

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

function mySettings(theme: AppTheme, enabled: boolean, taskDone = false): UserSettingsResponse {
  return { appearance: { theme }, notifications: { enabled, task_done: taskDone } };
}

function orgSettings(overrides: Partial<ToolsSettings> = {}): OrgSettingsResponse {
  return { tools: tools(overrides) };
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

type StatusAnswer = OAuthConnectionStatus | Error;

/** Answers `getOAuthStatus(provider)` per provider (an Error rejects). */
function statusesAre(answers: { google: StatusAnswer; microsoft: StatusAnswer }): void {
  mockedGetOAuthStatus.mockImplementation(async (provider) => {
    const answer = answers[provider];
    if (answer instanceof Error) throw answer;
    return answer;
  });
}

/** The providers `getOAuthStatus` was asked about, sorted. */
function statusRequests(): string[] {
  return mockedGetOAuthStatus.mock.calls.map(([provider]) => String(provider)).sort();
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
  it('starts on light, notifications on, both accounts disconnected and every org tool enabled', () => {
    const store = useSettingsStore();

    expect({
      theme: store.theme,
      notificationsEnabled: store.notificationsEnabled,
      connectedAccounts: store.connectedAccounts,
      tools: store.tools,
      loading: store.loading,
      error: store.error,
    }).toEqual({
      theme: 'light',
      notificationsEnabled: true,
      connectedAccounts: { google: DISCONNECTED, microsoft: DISCONNECTED },
      tools: tools(),
      loading: false,
      error: null,
    });
  });

  // Regression guard (issue #143: the local files tool is gone).
  it('default tools cover exactly the seven tool services, with no files key', () => {
    expect(Object.keys(useSettingsStore().tools).sort()).toEqual([...TOOL_NAMES].sort());
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
    'when the reset %s it never disconnects, patches or asks for the OAuth status, and keeps accounts, tools and session',
    async (_label, succeeds) => {
      const store = useSettingsStore();
      statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
      await store.loadConnections();
      mockedGetOrgSettings.mockResolvedValueOnce(orgSettings({ gmail: false, onedrive: false }));
      await store.loadOrgTools();
      const sessionBefore = store.sessionId;
      const statusRequestsBefore = mockedGetOAuthStatus.mock.calls.length;
      if (succeeds) {
        mockedResetMySettings.mockResolvedValueOnce(mySettings('light', true, false));
      } else {
        mockedResetMySettings.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
      }

      await outcomeOf(store.resetSettings());

      expect({
        resets: mockedResetMySettings.mock.calls.length,
        disconnects: mockedDisconnectOAuth.mock.calls.length,
        orgPatches: mockedPatchOrgSettings.mock.calls.length,
        userPatches: mockedPatchMySettings.mock.calls.length,
        statusRequests: mockedGetOAuthStatus.mock.calls.length - statusRequestsBefore,
        accounts: store.connectedAccounts,
        tools: store.tools,
        sessionId: store.sessionId,
        sessionStored: localStorage.getItem(SESSION_STORAGE_KEY),
      }).toEqual({
        resets: 1,
        disconnects: 0,
        orgPatches: 0,
        userPatches: 0,
        statusRequests: 0,
        accounts: { google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED },
        tools: tools({ gmail: false, onedrive: false }),
        sessionId: sessionBefore,
        sessionStored: sessionBefore,
      });
    },
  );
});

// --- loadConnections: GET /api/oauth/{provider}/status --------------------

describe('settingsStore loadConnections', () => {
  it('asks for the google and microsoft status and stores both', async () => {
    statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
    const store = useSettingsStore();

    await store.loadConnections();

    expect({ requested: statusRequests(), accounts: store.connectedAccounts }).toEqual({
      requested: ['google', 'microsoft'],
      accounts: { google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED },
    });
  });

  it('stores the disconnected default for a provider whose status request fails', async () => {
    statusesAre({ google: new ApiError(503, 'Service Unavailable'), microsoft: MICROSOFT_CONNECTED });
    const store = useSettingsStore();

    await store.loadConnections();

    expect(store.connectedAccounts).toEqual({ google: DISCONNECTED, microsoft: MICROSOFT_CONNECTED });
  });

  it('resets a previously connected account whose status now fails', async () => {
    const store = useSettingsStore();
    statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
    await store.loadConnections();

    statusesAre({ google: GOOGLE_CONNECTED, microsoft: new TypeError('Failed to fetch') });
    await store.loadConnections();

    expect(store.connectedAccounts).toEqual({ google: GOOGLE_CONNECTED, microsoft: DISCONNECTED });
  });

  // Issue #237: a connected-but-unhealthy account must stay distinguishable
  // from a healthy one, so the store keeps each response's `healthy` verbatim.
  it.each([
    { google: true, microsoft: false },
    { google: false, microsoft: true },
  ])('keeps the healthy flag of each status response (google $google, microsoft $microsoft)', async (healthy) => {
    statusesAre({
      google: { ...GOOGLE_CONNECTED, healthy: healthy.google },
      microsoft: { ...MICROSOFT_CONNECTED, healthy: healthy.microsoft },
    });
    const store = useSettingsStore();

    await store.loadConnections();

    expect(store.connectedAccounts).toEqual({
      google: { ...GOOGLE_CONNECTED, healthy: healthy.google },
      microsoft: { ...MICROSOFT_CONNECTED, healthy: healthy.microsoft },
    });
  });

  it('never throws and shows both disconnected when both status requests fail', async () => {
    statusesAre({ google: new Error('down'), microsoft: new Error('down') });
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.loadConnections());

    expect({ outcome, accounts: store.connectedAccounts }).toEqual({
      outcome: 'resolved',
      accounts: { google: DISCONNECTED, microsoft: DISCONNECTED },
    });
  });

  it.each([
    ['a number', 42],
    ['an object', { address: 'alice@example.ch' }],
    ['an array', ['alice@example.ch']],
    ['a boolean', true],
    ['undefined', undefined],
  ])('stores a non-string email (%s) as null', async (_label, email) => {
    const crafted = { ...GOOGLE_CONNECTED, email } as unknown as OAuthConnectionStatus;
    statusesAre({ google: crafted, microsoft: DISCONNECTED });
    const store = useSettingsStore();

    await store.loadConnections();

    expect(store.connectedAccounts.google).toEqual({ ...GOOGLE_CONNECTED, email: null });
  });
});

// --- loadOrgTools: GET /api/org/settings ----------------------------------

describe('settingsStore loadOrgTools', () => {
  it('loads the org tools from GET /api/org/settings without touching user settings', async () => {
    mockedGetOrgSettings.mockResolvedValueOnce(orgSettings({ gmail: false, onedrive: false }));
    const store = useSettingsStore();

    await store.loadOrgTools();

    expect({
      requests: mockedGetOrgSettings.mock.calls.length,
      userRequests: mockedGetMySettings.mock.calls.length + mockedPatchMySettings.mock.calls.length,
      tools: store.tools,
    }).toEqual({ requests: 1, userRequests: 0, tools: tools({ gmail: false, onedrive: false }) });
  });

  it('keeps the current tools and never throws when the request fails', async () => {
    mockedGetOrgSettings
      .mockResolvedValueOnce(orgSettings({ outlook: false }))
      .mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Forbidden'));
    const store = useSettingsStore();
    await store.loadOrgTools();

    const outcome = await outcomeOf(store.loadOrgTools());

    expect({ outcome, tools: store.tools }).toEqual({
      outcome: 'resolved',
      tools: tools({ outlook: false }),
    });
  });
});

// --- setToolEnabled: PATCH /api/org/settings ------------------------------

describe('settingsStore setToolEnabled', () => {
  it.each(TOOL_NAMES)(
    'switches %s optimistically and sends only that tool to PATCH /api/org/settings',
    async (tool) => {
      const pending = deferred<OrgSettingsResponse>();
      mockedPatchOrgSettings.mockReturnValueOnce(pending.promise);
      const store = useSettingsStore();

      const done = outcomeOf(store.setToolEnabled(tool, false));
      const during = { ...store.tools };
      pending.resolve(orgSettings({ [tool]: false }));
      await done;

      expect({
        during,
        orgPatches: mockedPatchOrgSettings.mock.calls,
        userPatches: mockedPatchMySettings.mock.calls.length,
      }).toEqual({
        during: tools({ [tool]: false }),
        orgPatches: [[{ tools: { [tool]: false } }]],
        userPatches: 0,
      });
    },
  );

  it('applies the tools the server returns', async () => {
    // Another admin switched Outlook off meanwhile: the response is the stored truth.
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings({ gmail: false, outlook: false }));
    const store = useSettingsStore();

    await store.setToolEnabled('gmail', false);

    expect(store.tools).toEqual(tools({ gmail: false, outlook: false }));
  });

  it('adds the translated "Saved" success toast', async () => {
    mockedPatchOrgSettings.mockResolvedValueOnce(orgSettings({ memory: false }));

    await useSettingsStore().setToolEnabled('memory', false);

    expect(toastSummary()).toEqual([{ kind: 'success', title: en['toast.common.saved'] }]);
  });

  it('reverts the tool, shows an error toast and never throws when the save fails', async () => {
    mockedPatchOrgSettings.mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Forbidden'));
    const store = useSettingsStore();

    const outcome = await outcomeOf(store.setToolEnabled('outlook', false));

    expect({
      outcome,
      tools: store.tools,
      toasts: toastKinds(),
      orgPatches: mockedPatchOrgSettings.mock.calls,
    }).toEqual({
      outcome: 'resolved',
      tools: tools(),
      toasts: ['error'],
      orgPatches: [[{ tools: { outlook: false } }]],
    });
  });

  it('reverts only the failed tool while another toggle is still saving', async () => {
    const gmailSave = deferred<OrgSettingsResponse>();
    const memorySave = deferred<OrgSettingsResponse>();
    mockedPatchOrgSettings.mockReturnValueOnce(gmailSave.promise).mockReturnValueOnce(memorySave.promise);
    const store = useSettingsStore();

    const gmailDone = outcomeOf(store.setToolEnabled('gmail', false));
    const memoryDone = outcomeOf(store.setToolEnabled('memory', false));
    gmailSave.reject(new ApiError(500, 'Internal Server Error'));
    const gmailOutcome = await gmailDone;
    const afterFailure = { ...store.tools };
    memorySave.resolve(orgSettings({ memory: false }));
    await memoryDone;

    expect({ gmailOutcome, afterFailure, final: store.tools }).toEqual({
      gmailOutcome: 'resolved',
      afterFailure: tools({ memory: false }),
      final: tools({ memory: false }),
    });
  });
});

// --- disconnectGoogle / disconnectMicrosoft -------------------------------

describe('settingsStore disconnect', () => {
  const cases = [
    ['disconnectGoogle', 'google', 'toast.settings.googleDisconnected'],
    ['disconnectMicrosoft', 'microsoft', 'toast.settings.microsoftDisconnected'],
  ] as const;

  it.each(cases)(
    '%s disconnects %s, then refreshes both connection statuses (no user-settings reload)',
    async (action, provider, toastKey) => {
      mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
      const other = provider === 'google' ? 'microsoft' : 'google';
      const otherStatus = other === 'google' ? GOOGLE_CONNECTED : MICROSOFT_CONNECTED;
      statusesAre(
        provider === 'google'
          ? { google: DISCONNECTED, microsoft: MICROSOFT_CONNECTED }
          : { google: GOOGLE_CONNECTED, microsoft: DISCONNECTED },
      );
      const store = useSettingsStore();

      await store[action]();

      const disconnectedAt = mockedDisconnectOAuth.mock.invocationCallOrder[0];
      const firstStatusAt = Math.min(...mockedGetOAuthStatus.mock.invocationCallOrder);
      expect({
        disconnected: mockedDisconnectOAuth.mock.calls,
        requested: statusRequests(),
        refreshedAfterDisconnect: firstStatusAt > disconnectedAt,
        userRequests: mockedGetMySettings.mock.calls.length,
        accounts: store.connectedAccounts,
        toasts: toastSummary(),
      }).toEqual({
        disconnected: [[provider]],
        requested: ['google', 'microsoft'],
        refreshedAfterDisconnect: true,
        userRequests: 0,
        accounts: { [provider]: DISCONNECTED, [other]: otherStatus },
        toasts: [{ kind: 'success', title: en[toastKey] }],
      });
    },
  );

  it.each(cases)(
    '%s still toasts success and shows both disconnected when the %s refresh fails',
    async (action, _provider, toastKey) => {
      const store = useSettingsStore();
      statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
      await store.loadConnections();
      mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
      statusesAre({ google: new Error('down'), microsoft: new Error('down') });

      const outcome = await outcomeOf(store[action]());

      expect({ outcome, accounts: store.connectedAccounts, toasts: toastSummary() }).toEqual({
        outcome: 'resolved',
        accounts: { google: DISCONNECTED, microsoft: DISCONNECTED },
        toasts: [{ kind: 'success', title: en[toastKey] }],
      });
    },
  );

  // Regression guard: the failure path is unchanged.
  it.each(cases)('%s shows the disconnect-failed toast and never throws when disconnecting fails', async (action) => {
    mockedDisconnectOAuth.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error', 'Nope'));
    const store = useSettingsStore();

    const outcome = await outcomeOf(store[action]());

    expect({ outcome, toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      toasts: [{ kind: 'error', title: en['toast.settings.disconnectFailed.title'], body: 'Nope' }],
    });
  });
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
