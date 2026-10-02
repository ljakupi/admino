/**
 * Connections store tests (issue #162: the Tools page becomes "my
 * connections").
 *
 * `useConnectionsStore` (Pinia id 'connections') owns the caller's own Google
 * and Microsoft connections, which moved out of the settings store
 * (GH-162 §14):
 * - state: `accounts` (both providers start as the disconnected default
 *   `{ connected: false, healthy: false, email: null, data_residency: false,
 *   services: [] }`) and `loading` (false).
 * - `load()`: both `GET /api/oauth/{provider}/status` calls in parallel; a
 *   failed one becomes the disconnected default; a non-string email is stored
 *   as `null`; `loading` is true during the load and false after; never throws.
 * - `connect(provider)`: when the account can't connect (`canConnect` is
 *   false) no API call is made; under residency that shows the
 *   "Connection failed" toast with `toolsPage.residency.connectBlocked`.
 *   Otherwise it asks `GET /api/oauth/{provider}/authorize`; a non-https URL
 *   shows the "Connection failed" toast with `settings.error.unexpectedRedirect`
 *   and never navigates; an https URL stores `oauth_pending = provider` in
 *   sessionStorage, then sets `window.location.href`. An API error shows the
 *   "Connection failed" toast with the error message (fallback
 *   `settings.error.oauthStartFailed`). Never throws.
 * - `disconnect(provider)`: `DELETE /api/oauth/{provider}`, then `load()`,
 *   then the provider's "disconnected" success toast; a failure shows the
 *   "Disconnect failed" toast with the message (fallback
 *   `settings.error.disconnectFailed`). Allowed under residency (a kept,
 *   inactive connection can be removed). Never throws.
 *
 * Security notes: the residency gate and the https-only redirect are
 * client-side guards in front of the backend's 403 / redirect checks; the
 * store never navigates to a non-https URL. Toast copy comes from the i18n
 * catalogs. `@/api/settings` is mocked and `window.location`'s navigation is
 * spied on, so nothing touches the network or leaves the page.
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
import { useConnectionsStore } from '@/stores/connections';
import { useToastStore } from '@/stores/toasts';
import type { OAuthConnectionStatus, OAuthProvider } from '@/api/types';

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

const PROVIDERS: readonly OAuthProvider[] = ['google', 'microsoft'];
const PENDING_KEY = 'oauth_pending';

/** What the server says when the org's residency policy refuses a connect. */
const RESIDENCY_DETAIL = "Your organization's data residency policy doesn't allow Google or Microsoft accounts.";

const DISCONNECTED: OAuthConnectionStatus = {
  connected: false,
  healthy: false,
  email: null,
  data_residency: false,
  services: [],
};

const GOOGLE_CONNECTED: OAuthConnectionStatus = {
  connected: true,
  healthy: true,
  email: 'alice@example.ch',
  data_residency: false,
  services: [
    { tool: 'gmail', enabled: true },
    { tool: 'google_calendar', enabled: false },
    { tool: 'google_drive', enabled: true },
  ],
};

const MICROSOFT_CONNECTED: OAuthConnectionStatus = {
  connected: true,
  healthy: true,
  email: 'alice@contoso.example',
  data_residency: false,
  services: [
    { tool: 'outlook', enabled: true },
    { tool: 'outlook_calendar', enabled: true },
    { tool: 'onedrive', enabled: false },
  ],
};

const CONNECTED: Record<OAuthProvider, OAuthConnectionStatus> = {
  google: GOOGLE_CONNECTED,
  microsoft: MICROSOFT_CONNECTED,
};

const DISCONNECT_TOAST_KEY: Record<OAuthProvider, string> = {
  google: 'toast.settings.googleDisconnected',
  microsoft: 'toast.settings.microsoftDisconnected',
};

const AUTHORIZE_URL: Record<OAuthProvider, string> = {
  google: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=s1',
  microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&state=s2',
};

// --- Helpers ---------------------------------------------------------------

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

function other(provider: OAuthProvider): OAuthProvider {
  return provider === 'google' ? 'microsoft' : 'google';
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

/** Lets every pending microtask and zero-delay timer run. */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

type StatusAnswer = OAuthConnectionStatus | Error;

/** Answers `getOAuthStatus(provider)` per provider (an Error rejects). */
function statusesAre(answers: Record<OAuthProvider, StatusAnswer>): void {
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

/** A store whose accounts were loaded from `answers`, with the status mock call log cleared. */
async function loadedStore(answers: Record<OAuthProvider, StatusAnswer>): Promise<ReturnType<typeof useConnectionsStore>> {
  statusesAre(answers);
  const store = useConnectionsStore();
  await store.load();
  mockedGetOAuthStatus.mockClear();
  return store;
}

function toastSummary(): Array<{ kind: string; title: string; body?: string }> {
  return useToastStore().toasts.map(({ kind, title, body }) => (body === undefined ? { kind, title } : { kind, title, body }));
}

/** Every navigation the store attempted, and the pending marker at each `href` assignment. */
interface NavigationLog {
  hrefs: string[];
  pendingAtHref: Array<string | null>;
  other: unknown[];
}

let navigation: NavigationLog;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  setActivePinia(createPinia());
  mockedGetMySettings.mockReset();
  mockedPatchMySettings.mockReset();
  mockedGetOrgSettings.mockReset();
  mockedPatchOrgSettings.mockReset();
  mockedGetOAuthStatus.mockReset();
  mockedGetOAuthAuthorizeUrl.mockReset();
  mockedDisconnectOAuth.mockReset();

  const log: NavigationLog = { hrefs: [], pendingAtHref: [], other: [] };
  vi.spyOn(window.location, 'href', 'set').mockImplementation((url: string) => {
    log.hrefs.push(String(url));
    log.pendingAtHref.push(sessionStorage.getItem(PENDING_KEY));
  });
  vi.spyOn(window.location, 'assign').mockImplementation((url: string | URL) => {
    log.other.push(['assign', String(url)]);
  });
  vi.spyOn(window.location, 'replace').mockImplementation((url: string | URL) => {
    log.other.push(['replace', String(url)]);
  });
  navigation = log;
});

afterEach(() => {
  setLocale('en');
});

/** True when the store tried to leave the page in any way. */
function navigated(): boolean {
  return navigation.hrefs.length > 0 || navigation.other.length > 0;
}

// --- Initial state ----------------------------------------------------------

describe('connectionsStore initial state', () => {
  it('is the "connections" store with both accounts disconnected and not loading', () => {
    const store = useConnectionsStore();

    expect({ id: store.$id, accounts: store.accounts, loading: store.loading }).toEqual({
      id: 'connections',
      accounts: { google: DISCONNECTED, microsoft: DISCONNECTED },
      loading: false,
    });
  });

  it('asks nothing of the server until load() is called', () => {
    useConnectionsStore();

    expect(mockedGetOAuthStatus.mock.calls.length + mockedGetOAuthAuthorizeUrl.mock.calls.length).toBe(0);
  });
});

// --- load: GET /api/oauth/{provider}/status --------------------------------

describe('connectionsStore load', () => {
  it('asks for the google and microsoft status and stores both verbatim', async () => {
    statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
    const store = useConnectionsStore();

    await store.load();

    expect({ requested: statusRequests(), accounts: store.accounts }).toEqual({
      requested: ['google', 'microsoft'],
      accounts: { google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED },
    });
  });

  it('asks for both statuses in parallel and is loading until both answer', async () => {
    const google = deferred<OAuthConnectionStatus>();
    const microsoft = deferred<OAuthConnectionStatus>();
    mockedGetOAuthStatus.mockImplementation((provider) => (provider === 'google' ? google.promise : microsoft.promise));
    const store = useConnectionsStore();

    const done = outcomeOf(store.load());
    await flush();
    const whilePending = { requested: statusRequests(), loading: store.loading };
    google.resolve(GOOGLE_CONNECTED);
    await flush();
    const afterOne = store.loading;
    microsoft.resolve(MICROSOFT_CONNECTED);
    const outcome = await done;

    expect({ whilePending, afterOne, outcome, after: store.loading }).toEqual({
      whilePending: { requested: ['google', 'microsoft'], loading: true },
      afterOne: true,
      outcome: 'resolved',
      after: false,
    });
  });

  it('keeps the data_residency flag and the per-service switches of each response', async () => {
    const googleResidency: OAuthConnectionStatus = { ...GOOGLE_CONNECTED, data_residency: true };
    const microsoftResidency: OAuthConnectionStatus = { ...DISCONNECTED, data_residency: true, services: MICROSOFT_CONNECTED.services };
    statusesAre({ google: googleResidency, microsoft: microsoftResidency });
    const store = useConnectionsStore();

    await store.load();

    expect(store.accounts).toEqual({ google: googleResidency, microsoft: microsoftResidency });
  });

  it.each([
    { google: true, microsoft: false },
    { google: false, microsoft: true },
  ])('keeps the healthy flag of each response (google $google, microsoft $microsoft)', async (healthy) => {
    statusesAre({
      google: { ...GOOGLE_CONNECTED, healthy: healthy.google },
      microsoft: { ...MICROSOFT_CONNECTED, healthy: healthy.microsoft },
    });
    const store = useConnectionsStore();

    await store.load();

    expect(store.accounts).toEqual({
      google: { ...GOOGLE_CONNECTED, healthy: healthy.google },
      microsoft: { ...MICROSOFT_CONNECTED, healthy: healthy.microsoft },
    });
  });

  it('stores the disconnected default for a provider whose status request fails', async () => {
    statusesAre({ google: new ApiError(503, 'Service Unavailable'), microsoft: MICROSOFT_CONNECTED });
    const store = useConnectionsStore();

    await store.load();

    expect(store.accounts).toEqual({ google: DISCONNECTED, microsoft: MICROSOFT_CONNECTED });
  });

  it('resets a previously connected account whose status now fails', async () => {
    const store = await loadedStore({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });

    statusesAre({ google: GOOGLE_CONNECTED, microsoft: new TypeError('Failed to fetch') });
    await store.load();

    expect(store.accounts).toEqual({ google: GOOGLE_CONNECTED, microsoft: DISCONNECTED });
  });

  it('resets a previous residency flag to the default when the status now fails', async () => {
    const store = await loadedStore({
      google: { ...GOOGLE_CONNECTED, data_residency: true },
      microsoft: { ...MICROSOFT_CONNECTED, data_residency: true },
    });

    statusesAre({ google: new ApiError(403, 'Forbidden', 'Forbidden'), microsoft: new ApiError(403, 'Forbidden', 'Forbidden') });
    await store.load();

    expect(store.accounts).toEqual({ google: DISCONNECTED, microsoft: DISCONNECTED });
  });

  it('never throws, stops loading and shows both disconnected when both status requests fail', async () => {
    statusesAre({ google: new Error('down'), microsoft: new Error('down') });
    const store = useConnectionsStore();

    const outcome = await outcomeOf(store.load());

    expect({ outcome, loading: store.loading, accounts: store.accounts }).toEqual({
      outcome: 'resolved',
      loading: false,
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
    statusesAre({ google: crafted, microsoft: { ...MICROSOFT_CONNECTED, email } as unknown as OAuthConnectionStatus });
    const store = useConnectionsStore();

    await store.load();

    expect(store.accounts).toEqual({
      google: { ...GOOGLE_CONNECTED, email: null },
      microsoft: { ...MICROSOFT_CONNECTED, email: null },
    });
  });

  it('never asks for the user or org settings', async () => {
    statusesAre({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });

    await useConnectionsStore().load();

    expect(
      mockedGetMySettings.mock.calls.length +
        mockedPatchMySettings.mock.calls.length +
        mockedGetOrgSettings.mock.calls.length +
        mockedPatchOrgSettings.mock.calls.length,
    ).toBe(0);
  });
});

// --- connect: GET /api/oauth/{provider}/authorize ---------------------------

describe('connectionsStore connect', () => {
  it.each(PROVIDERS)(
    'asks for the %s authorize url, stores the pending provider, then navigates to the https url',
    async (provider) => {
      mockedGetOAuthAuthorizeUrl.mockResolvedValueOnce({ url: AUTHORIZE_URL[provider] });
      const store = useConnectionsStore();

      const outcome = await outcomeOf(store.connect(provider));

      expect({
        outcome,
        authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls,
        pending: sessionStorage.getItem(PENDING_KEY),
        hrefs: navigation.hrefs,
        pendingAtHref: navigation.pendingAtHref,
        otherNavigation: navigation.other,
        toasts: toastSummary(),
      }).toEqual({
        outcome: 'resolved',
        authorizeCalls: [[provider]],
        pending: provider,
        hrefs: [AUTHORIZE_URL[provider]],
        pendingAtHref: [provider],
        otherNavigation: [],
        toasts: [],
      });
    },
  );

  it.each(PROVIDERS)('lets a connected but unhealthy %s account reconnect', async (provider) => {
    const store = await loadedStore({
      google: { ...GOOGLE_CONNECTED, healthy: provider !== 'google' },
      microsoft: { ...MICROSOFT_CONNECTED, healthy: provider !== 'microsoft' },
    });
    mockedGetOAuthAuthorizeUrl.mockResolvedValueOnce({ url: AUTHORIZE_URL[provider] });

    await store.connect(provider);

    expect({ authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls, hrefs: navigation.hrefs }).toEqual({
      authorizeCalls: [[provider]],
      hrefs: [AUTHORIZE_URL[provider]],
    });
  });

  it.each(PROVIDERS)(
    'makes no API call and never navigates when %s is already connected and healthy',
    async (provider) => {
      const store = await loadedStore({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });

      const outcome = await outcomeOf(store.connect(provider));

      expect({
        outcome,
        authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls.length,
        pending: sessionStorage.getItem(PENDING_KEY),
        navigated: navigated(),
      }).toEqual({ outcome: 'resolved', authorizeCalls: 0, pending: null, navigated: false });
    },
  );

  it.each(PROVIDERS)(
    'under residency makes no API call for %s and shows the "connect blocked" error toast',
    async (provider) => {
      const store = await loadedStore({
        google: { ...DISCONNECTED, data_residency: true },
        microsoft: { ...DISCONNECTED, data_residency: true },
      });

      const outcome = await outcomeOf(store.connect(provider));

      expect({
        outcome,
        authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls.length,
        pending: sessionStorage.getItem(PENDING_KEY),
        navigated: navigated(),
        toasts: toastSummary(),
      }).toEqual({
        outcome: 'resolved',
        authorizeCalls: 0,
        pending: null,
        navigated: false,
        toasts: [
          {
            kind: 'error',
            title: text(EN, 'toast.settings.connectionFailed.title'),
            body: text(EN, 'toolsPage.residency.connectBlocked'),
          },
        ],
      });
    },
  );

  it('under residency also blocks a kept healthy connection from reconnecting', async () => {
    const store = await loadedStore({
      google: { ...GOOGLE_CONNECTED, data_residency: true },
      microsoft: { ...MICROSOFT_CONNECTED, data_residency: true },
    });

    await store.connect('google');

    expect({ authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls.length, navigated: navigated(), toasts: toastSummary() }).toEqual({
      authorizeCalls: 0,
      navigated: false,
      toasts: [
        {
          kind: 'error',
          title: text(EN, 'toast.settings.connectionFailed.title'),
          body: text(EN, 'toolsPage.residency.connectBlocked'),
        },
      ],
    });
  });

  it('reads residency per provider: a residency microsoft status blocks only microsoft', async () => {
    const store = await loadedStore({ google: DISCONNECTED, microsoft: { ...DISCONNECTED, data_residency: true } });
    mockedGetOAuthAuthorizeUrl.mockResolvedValueOnce({ url: AUTHORIZE_URL.google });

    await store.connect('microsoft');
    await store.connect('google');

    expect({ authorizeCalls: mockedGetOAuthAuthorizeUrl.mock.calls, hrefs: navigation.hrefs }).toEqual({
      authorizeCalls: [['google']],
      hrefs: [AUTHORIZE_URL.google],
    });
  });

  it('takes the residency toast copy from the active locale', async () => {
    const store = await loadedStore({
      google: { ...DISCONNECTED, data_residency: true },
      microsoft: { ...DISCONNECTED, data_residency: true },
    });
    setLocale('fr');

    await store.connect('microsoft');

    expect(toastSummary()).toEqual([
      {
        kind: 'error',
        title: text(FR, 'toast.settings.connectionFailed.title'),
        body: text(FR, 'toolsPage.residency.connectBlocked'),
      },
    ]);
  });

  it.each([
    ['plain http', 'http://accounts.google.com/o/oauth2/v2/auth?state=s1'],
    ['javascript:', 'javascript:alert(1)'],
    ['data:', 'data:text/html,<script>alert(1)</script>'],
    ['ftp', 'ftp://accounts.example/auth'],
  ])(
    'refuses a %s authorize url: unexpected-redirect toast, no pending marker, no navigation',
    async (_label, url) => {
      mockedGetOAuthAuthorizeUrl.mockResolvedValueOnce({ url });
      const store = useConnectionsStore();

      const outcome = await outcomeOf(store.connect('google'));

      expect({
        outcome,
        pending: sessionStorage.getItem(PENDING_KEY),
        navigated: navigated(),
        toasts: toastSummary(),
      }).toEqual({
        outcome: 'resolved',
        pending: null,
        navigated: false,
        toasts: [
          {
            kind: 'error',
            title: text(EN, 'toast.settings.connectionFailed.title'),
            body: text(EN, 'settings.error.unexpectedRedirect'),
          },
        ],
      });
    },
  );

  it('refuses an unparsable authorize url with a "Connection failed" toast and never navigates', async () => {
    mockedGetOAuthAuthorizeUrl.mockResolvedValueOnce({ url: '//evil.example/authorize' });
    const store = useConnectionsStore();

    const outcome = await outcomeOf(store.connect('microsoft'));

    expect({
      outcome,
      pending: sessionStorage.getItem(PENDING_KEY),
      navigated: navigated(),
      toasts: useToastStore().toasts.map(({ kind, title }) => ({ kind, title })),
    }).toEqual({
      outcome: 'resolved',
      pending: null,
      navigated: false,
      toasts: [{ kind: 'error', title: text(EN, 'toast.settings.connectionFailed.title') }],
    });
  });

  it.each([
    ['the residency 403', new ApiError(403, 'Forbidden', RESIDENCY_DETAIL), RESIDENCY_DETAIL],
    ['a role 403', new ApiError(403, 'Forbidden', 'Forbidden'), 'Forbidden'],
    ['a 500', new ApiError(500, 'Internal Server Error', 'OAuth configuration error.'), 'OAuth configuration error.'],
    ['a network failure', new TypeError('Failed to fetch'), 'Failed to fetch'],
  ])(
    'shows the "Connection failed" toast with the message of %s, never navigates and never throws',
    async (_label, rejection, body) => {
      mockedGetOAuthAuthorizeUrl.mockRejectedValueOnce(rejection);
      const store = useConnectionsStore();

      const outcome = await outcomeOf(store.connect('google'));

      expect({
        outcome,
        pending: sessionStorage.getItem(PENDING_KEY),
        navigated: navigated(),
        toasts: toastSummary(),
      }).toEqual({
        outcome: 'resolved',
        pending: null,
        navigated: false,
        toasts: [{ kind: 'error', title: text(EN, 'toast.settings.connectionFailed.title'), body }],
      });
    },
  );

  it('falls back to the translated oauth-start-failed body for a non-Error rejection', async () => {
    mockedGetOAuthAuthorizeUrl.mockRejectedValueOnce('offline');

    const outcome = await outcomeOf(useConnectionsStore().connect('microsoft'));

    expect({ outcome, toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      toasts: [
        {
          kind: 'error',
          title: text(EN, 'toast.settings.connectionFailed.title'),
          body: text(EN, 'settings.error.oauthStartFailed'),
        },
      ],
    });
  });
});

// --- disconnect: DELETE /api/oauth/{provider} -------------------------------

describe('connectionsStore disconnect', () => {
  it.each(PROVIDERS)(
    'disconnects %s, then refreshes both statuses and shows the provider\'s success toast',
    async (provider) => {
      const store = await loadedStore({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
      mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
      statusesAre(
        provider === 'google'
          ? { google: DISCONNECTED, microsoft: MICROSOFT_CONNECTED }
          : { google: GOOGLE_CONNECTED, microsoft: DISCONNECTED },
      );

      const outcome = await outcomeOf(store.disconnect(provider));

      const disconnectedAt = mockedDisconnectOAuth.mock.invocationCallOrder[0];
      const firstStatusAt = Math.min(...mockedGetOAuthStatus.mock.invocationCallOrder);
      expect({
        outcome,
        disconnected: mockedDisconnectOAuth.mock.calls,
        requested: statusRequests(),
        refreshedAfterDisconnect: firstStatusAt > disconnectedAt,
        accounts: store.accounts,
        toasts: toastSummary(),
      }).toEqual({
        outcome: 'resolved',
        disconnected: [[provider]],
        requested: ['google', 'microsoft'],
        refreshedAfterDisconnect: true,
        accounts: { [provider]: DISCONNECTED, [other(provider)]: CONNECTED[other(provider)] },
        toasts: [{ kind: 'success', title: text(EN, DISCONNECT_TOAST_KEY[provider]) }],
      });
    },
  );

  it.each(PROVIDERS)(
    'still toasts success and shows both disconnected when the refresh after disconnecting %s fails',
    async (provider) => {
      const store = await loadedStore({ google: GOOGLE_CONNECTED, microsoft: MICROSOFT_CONNECTED });
      mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
      statusesAre({ google: new Error('down'), microsoft: new Error('down') });

      const outcome = await outcomeOf(store.disconnect(provider));

      expect({ outcome, accounts: store.accounts, toasts: toastSummary() }).toEqual({
        outcome: 'resolved',
        accounts: { google: DISCONNECTED, microsoft: DISCONNECTED },
        toasts: [{ kind: 'success', title: text(EN, DISCONNECT_TOAST_KEY[provider]) }],
      });
    },
  );

  it.each(PROVIDERS)('still disconnects a kept %s connection under residency', async (provider) => {
    const store = await loadedStore({
      google: { ...GOOGLE_CONNECTED, data_residency: true },
      microsoft: { ...MICROSOFT_CONNECTED, data_residency: true },
    });
    mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
    statusesAre({
      google: { ...DISCONNECTED, data_residency: true },
      microsoft: { ...DISCONNECTED, data_residency: true },
    });

    await store.disconnect(provider);

    expect({
      disconnected: mockedDisconnectOAuth.mock.calls,
      account: store.accounts[provider],
      toasts: toastSummary(),
    }).toEqual({
      disconnected: [[provider]],
      account: { ...DISCONNECTED, data_residency: true },
      toasts: [{ kind: 'success', title: text(EN, DISCONNECT_TOAST_KEY[provider]) }],
    });
  });

  it('titles the success toast with the fr catalog string under fr', async () => {
    setLocale('fr');
    mockedDisconnectOAuth.mockResolvedValueOnce(undefined);
    statusesAre({ google: DISCONNECTED, microsoft: DISCONNECTED });

    await useConnectionsStore().disconnect('microsoft');

    expect(toastSummary()).toEqual([{ kind: 'success', title: text(FR, 'toast.settings.microsoftDisconnected') }]);
  });

  it.each(PROVIDERS)(
    'shows the "Disconnect failed" toast with the error message and never throws when disconnecting %s fails',
    async (provider) => {
      mockedDisconnectOAuth.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error', 'Nope'));
      const store = useConnectionsStore();

      const outcome = await outcomeOf(store.disconnect(provider));

      expect({ outcome, disconnected: mockedDisconnectOAuth.mock.calls, toasts: toastSummary() }).toEqual({
        outcome: 'resolved',
        disconnected: [[provider]],
        toasts: [{ kind: 'error', title: text(EN, 'toast.settings.disconnectFailed.title'), body: 'Nope' }],
      });
    },
  );

  it('falls back to the translated disconnect-failed body for a non-Error rejection', async () => {
    mockedDisconnectOAuth.mockRejectedValueOnce({ detail: 'not an Error' });

    const outcome = await outcomeOf(useConnectionsStore().disconnect('google'));

    expect({ outcome, toasts: toastSummary() }).toEqual({
      outcome: 'resolved',
      toasts: [
        {
          kind: 'error',
          title: text(EN, 'toast.settings.disconnectFailed.title'),
          body: text(EN, 'settings.error.disconnectFailed'),
        },
      ],
    });
  });

  it('takes the failure toast title and fallback body from the active locale', async () => {
    setLocale('fr');
    mockedDisconnectOAuth.mockRejectedValueOnce('offline');

    await outcomeOf(useConnectionsStore().disconnect('microsoft'));

    expect(toastSummary()).toEqual([
      {
        kind: 'error',
        title: text(FR, 'toast.settings.disconnectFailed.title'),
        body: text(FR, 'settings.error.disconnectFailed'),
      },
    ]);
  });
});
