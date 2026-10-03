/**
 * Account store tests (issue #166: account self-service — profile, languages,
 * timezone, personal instructions, password and sessions).
 *
 * `useAccountStore` (Pinia setup store, `stores/account.ts`) owns the "My
 * account" settings section. No action ever throws; failures come back as a
 * catalog key (`Result = { ok: true } | { ok: false; messageKey }`) or a
 * translated-key error field.
 *
 * - `load()`: `GET /api/me` → `account`; a failure sets `loadError =
 *   'account.error.load'` and keeps the previous account.
 * - `saveProfile(draft)`: client-side checks first (no request on an issue),
 *   no request when nothing changed, else `PATCH /api/me` with exactly the
 *   changed fields; success updates `account`, syncs the auth store
 *   (`me.ui_language` / `me.response_language`, UI locale) and adds the
 *   'account.toast.saved' success toast. 422 → 'account.error.invalid', 429 →
 *   'auth.error.rateLimited', anything else → 'account.error.generic'.
 * - `setUiLanguage(lang)`: switches the UI locale before the PATCH resolves;
 *   a failure reverts to the previous locale.
 * - `presetTimezone()`: after a login / invitation accept, presets a NULL
 *   stored timezone to the browser's zone (falling back to Europe/Zurich when
 *   the server refuses it with a 422); swallows every error; runs at most once
 *   per user per app load (a fresh Pinia stands for a fresh app load).
 * - `changePassword(current, next, confirm, email)`: client-side policy and a
 *   blank current password are refused without a request; success ends the
 *   local session through `auth.forgetSession()` (no logout API call, no
 *   session-expired toast); 403 → 'account.password.error.current' and the
 *   user stays signed in. No password is ever kept in any store state.
 * - `loadSessions()` (sorted: current first, then last seen, newest first) and
 *   `revokeSession(id)` (404 counts as gone; revoking the current session ends
 *   the local session).
 * - `reset()` clears everything; the auth store's `logout()` and
 *   `forgetSession()` call it.
 *
 * `@/api/account` and `@/api/auth` are mocked (nothing touches the network);
 * `ApiError`, the i18n singleton, the auth/chat/toast stores and the
 * `services/account` / `services/passwordPolicy` logic are the real ones. The
 * browser's timezone is stubbed through `Intl.DateTimeFormat`'s
 * `resolvedOptions()`. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import {
  changeMyPassword,
  getMyAccount,
  listMySessions,
  patchMyAccount,
  revokeMySession,
} from '@/api/account';
import { getMe, logout as apiLogout } from '@/api/auth';
import { ApiError } from '@/api/client';
import { locale, setLocale, t } from '@/i18n';
import { useAccountStore } from '@/stores/account';
import { useAuthStore } from '@/stores/auth';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';
import type { AccountDraft } from '@/services/account';
import type { MeResponse, MyAccount, SessionSummary, ThreadItem } from '@/api/types';

vi.mock('@/api/account', () => ({
  getMyAccount: vi.fn(),
  patchMyAccount: vi.fn(),
  changeMyPassword: vi.fn(),
  listMySessions: vi.fn(),
  revokeMySession: vi.fn(),
}));

vi.mock('@/api/auth', () => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  getInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

const api = {
  getMyAccount: vi.mocked(getMyAccount),
  patchMyAccount: vi.mocked(patchMyAccount),
  changeMyPassword: vi.mocked(changeMyPassword),
  listMySessions: vi.mocked(listMySessions),
  revokeMySession: vi.mocked(revokeMySession),
};

type ApiName = keyof typeof api;

/** Every account API function with zero calls. */
const NO_CALLS: Readonly<Record<ApiName, number>> = {
  getMyAccount: 0,
  patchMyAccount: 0,
  changeMyPassword: 0,
  listMySessions: 0,
  revokeMySession: 0,
};

/** How many times each account API function was called. */
function apiCalls(): Record<ApiName, number> {
  return {
    getMyAccount: api.getMyAccount.mock.calls.length,
    patchMyAccount: api.patchMyAccount.mock.calls.length,
    changeMyPassword: api.changeMyPassword.mock.calls.length,
    listMySessions: api.listMySessions.mock.calls.length,
    revokeMySession: api.revokeMySession.mock.calls.length,
  };
}

/** Forgets the calls the test setup made, keeping queued results. */
function clearApiCalls(): void {
  for (const mock of Object.values(api)) mock.mockClear();
}

const mockedGetMe = vi.mocked(getMe);
const mockedLogout = vi.mocked(apiLogout);

const ORG_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';
const ALICE_ID = '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90';
const BOB_ID = '3c8d1f7a-9e2b-4a6c-8d5f-0e1a2b3c4d5e';
const EMAIL = 'alice@example.ch';
const CURRENT_PASSWORD = 'Plumbago-Lantern-4417';
const NEW_PASSWORD = 'Saffron-Glacier-9032';
const BROWSER_ZONE = 'America/New_York';
const DEFAULT_ZONE = 'Europe/Zurich';

const CURRENT_SESSION_ID = '4e1f2a3b-5c6d-4e7f-8a9b-0c1d2e3f4a5b';
const LAPTOP_SESSION_ID = '9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d';
const PHONE_SESSION_ID = 'c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f';

function member(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    user_id: ALICE_ID,
    kind: 'member',
    org_id: ORG_ID,
    role: 'editor',
    ui_language: 'en',
    response_language: null,
    ...overrides,
  };
}

function account(overrides: Partial<MyAccount> = {}): MyAccount {
  return {
    email: EMAIL,
    name: 'Alice Example',
    ui_language: 'en',
    response_language: null,
    timezone: DEFAULT_ZONE,
    personal_instructions: 'Sign off with "Best, Alice".',
    ...overrides,
  };
}

/** The draft the profile form holds for `account()` unchanged. */
function draft(overrides: Partial<AccountDraft> = {}): AccountDraft {
  return {
    name: 'Alice Example',
    response_language: null,
    timezone: DEFAULT_ZONE,
    personal_instructions: 'Sign off with "Best, Alice".',
    ...overrides,
  };
}

function session(overrides: Partial<SessionSummary> = {}): SessionSummary {
  return {
    id: LAPTOP_SESSION_ID,
    created_at: '2026-09-20T08:00:00Z',
    last_seen_at: '2026-10-01T09:00:00Z',
    expires_at: '2026-10-20T08:00:00Z',
    ip: '203.0.113.7',
    user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15',
    current: false,
    ...overrides,
  };
}

/** The current session was last seen before the phone, so "current first" isn't just "newest first". */
const CURRENT = session({ id: CURRENT_SESSION_ID, last_seen_at: '2026-09-30T12:00:00Z', current: true });
const LAPTOP = session({ id: LAPTOP_SESSION_ID, last_seen_at: '2026-10-01T09:00:00Z' });
const PHONE = session({ id: PHONE_SESSION_ID, last_seen_at: '2026-10-02T18:30:00Z', user_agent: null, ip: null });
const SORTED_SESSIONS: readonly SessionSummary[] = [CURRENT, PHONE, LAPTOP];

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Lets every queued promise callback (mocked API calls included) run. */
function flushPromises(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function stubBrowserLanguages(languages: readonly string[]): void {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(languages);
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(languages[0] ?? '');
}

/** Makes `Intl.DateTimeFormat().resolvedOptions().timeZone` report `zone`. */
function stubBrowserTimezone(zone: string): void {
  const base = new Intl.DateTimeFormat('en').resolvedOptions();
  vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockReturnValue({ ...base, timeZone: zone });
}

/** Signs in through `ensureLoaded` (which never presets the timezone). */
async function signIn(me: MeResponse = member()): Promise<void> {
  mockedGetMe.mockResolvedValueOnce(me);
  await useAuthStore().ensureLoaded();
  if (!useAuthStore().isAuthenticated) throw new Error('test setup: sign-in failed');
}

/** Loads `saved` into the account store and forgets the setup call. */
async function loadAccount(saved: MyAccount = account()): Promise<void> {
  api.getMyAccount.mockResolvedValueOnce(saved);
  await useAccountStore().load();
  if (useAccountStore().account === null) throw new Error('test setup: load failed');
  clearApiCalls();
}

/** Loads the three sessions (unsorted) into the account store and forgets the setup call. */
async function loadSessions(): Promise<void> {
  api.listMySessions.mockResolvedValueOnce([LAPTOP, CURRENT, PHONE]);
  await useAccountStore().loadSessions();
  clearApiCalls();
}

/** Puts one user message into the chat thread, so a test can see whether it is cleared. */
function seedThread(): void {
  const item: ThreadItem = {
    type: 'message',
    data: { id: 'm-seed', role: 'user', content: 'What is on my calendar?', timestamp: new Date() },
  };
  useChatStore().thread.push(item);
}

function toastSummary(): Array<{ kind: string; title: string }> {
  return useToastStore().toasts.map(({ kind, title }) => ({ kind, title }));
}

/** Every key/value pair of a Web Storage area. */
function storageDump(storage: Storage): Record<string, string | null> {
  const dump: Record<string, string | null> = {};
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (key !== null) dump[key] = storage.getItem(key);
  }
  return dump;
}

/** Whether `needle` appears anywhere in `value` (walks objects, arrays, Maps and Sets). */
function containsString(value: unknown, needle: string, seen: Set<unknown> = new Set()): boolean {
  if (typeof value === 'string') return value.includes(needle);
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (value instanceof Map) {
    return [...value.entries()].some(([k, v]) => containsString(k, needle, seen) || containsString(v, needle, seen));
  }
  if (value instanceof Set) return [...value].some((v) => containsString(v, needle, seen));
  return Object.values(value).some((v) => containsString(v, needle, seen));
}

/** Whether either password is kept in any store state or in web storage. */
function passwordsKept(): { current: boolean; next: boolean } {
  const everything = [
    useAccountStore().$state,
    useAuthStore().$state,
    useToastStore().$state,
    storageDump(localStorage),
    storageDump(sessionStorage),
  ];
  return {
    current: containsString(everything, CURRENT_PASSWORD),
    next: containsString(everything, NEW_PASSWORD),
  };
}

const NOTHING_KEPT = { current: false, next: false };

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  setActivePinia(createPinia());
  for (const mock of Object.values(api)) mock.mockReset();
  mockedGetMe.mockReset();
  mockedLogout.mockReset();
  setLocale('en');
  stubBrowserLanguages(['en-US']);
  stubBrowserTimezone(BROWSER_ZONE);
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('accountStore initial state', () => {
  it('starts empty, idle and without errors', () => {
    const store = useAccountStore();

    expect({
      account: store.account,
      loading: store.loading,
      saving: store.saving,
      loadError: store.loadError,
      sessions: store.sessions,
      sessionsLoading: store.sessionsLoading,
      sessionsError: store.sessionsError,
      revokingId: store.revokingId,
      changingPassword: store.changingPassword,
    }).toEqual({
      account: null,
      loading: false,
      saving: false,
      loadError: null,
      sessions: [],
      sessionsLoading: false,
      sessionsError: null,
      revokingId: null,
      changingPassword: false,
    });
  });
});

// --- load -----------------------------------------------------------------

describe('accountStore load', () => {
  it('fetches GET /api/me once and keeps the account', async () => {
    const saved = account({ response_language: 'it', timezone: 'Europe/Berlin' });
    api.getMyAccount.mockResolvedValueOnce(saved);
    const store = useAccountStore();

    await store.load();

    expect({ calls: apiCalls(), account: store.account, loadError: store.loadError }).toEqual({
      calls: { ...NO_CALLS, getMyAccount: 1 },
      account: saved,
      loadError: null,
    });
  });

  it('is loading while the request runs and idle afterwards', async () => {
    const pending = deferred<MyAccount>();
    api.getMyAccount.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.load();
    const loadingWhilePending = store.loading;
    pending.resolve(account());
    await running;

    expect({ loadingWhilePending, loadingAfter: store.loading }).toEqual({
      loadingWhilePending: true,
      loadingAfter: false,
    });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 404', () => new ApiError(404, 'Not Found', 'Account not found')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])("sets loadError 'account.error.load' on %s, keeps the previous account and never throws", async (_label, makeError) => {
    const store = useAccountStore();
    await loadAccount(account({ name: 'Alice Earlier' }));
    api.getMyAccount.mockRejectedValueOnce(makeError());

    await expect(store.load()).resolves.toBeUndefined();
    expect({ account: store.account, loadError: store.loadError, loading: store.loading }).toEqual({
      account: account({ name: 'Alice Earlier' }),
      loadError: 'account.error.load',
      loading: false,
    });
  });

  it('clears an earlier loadError on a successful reload', async () => {
    const store = useAccountStore();
    api.getMyAccount.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    await store.load();
    const errorAfterFailure = store.loadError;
    api.getMyAccount.mockResolvedValueOnce(account());

    await store.load();

    expect({ errorAfterFailure, loadError: store.loadError, account: store.account }).toEqual({
      errorAfterFailure: 'account.error.load',
      loadError: null,
      account: account(),
    });
  });
});

// --- saveProfile ----------------------------------------------------------

describe('accountStore saveProfile validation', () => {
  it.each([
    ['a blank name', draft({ name: '   ' }), 'account.error.nameRequired'],
    ['a name over 120 characters', draft({ name: 'a'.repeat(121) }), 'account.error.nameTooLong'],
    [
      'instructions over 1500 characters',
      draft({ personal_instructions: 'x'.repeat(1501) }),
      'account.error.instructionsTooLong',
    ],
    [
      'a blank name and too-long instructions (first issue wins)',
      draft({ name: '', personal_instructions: 'x'.repeat(1501) }),
      'account.error.nameRequired',
    ],
    [
      'a too-long name and too-long instructions (first issue wins)',
      draft({ name: 'b'.repeat(121), personal_instructions: 'x'.repeat(1501) }),
      'account.error.nameTooLong',
    ],
  ] as Array<[string, AccountDraft, string]>)('refuses %s with %j and makes no request', async (_label, input, key) => {
    await signIn();
    await loadAccount();
    const store = useAccountStore();

    const result = await store.saveProfile(input);

    expect({ result, calls: apiCalls(), account: store.account, toasts: toastSummary() }).toEqual({
      result: { ok: false, messageKey: key },
      calls: NO_CALLS,
      account: account(),
      toasts: [],
    });
  });

  it.each([
    ['the unchanged draft', draft()],
    ['a name that differs only by surrounding spaces', draft({ name: '  Alice Example  ' })],
  ])('returns ok without a request for %s', async (_label, input) => {
    await signIn();
    await loadAccount();
    const store = useAccountStore();

    const result = await store.saveProfile(input);

    expect({ result, calls: apiCalls(), account: store.account }).toEqual({
      result: { ok: true },
      calls: NO_CALLS,
      account: account(),
    });
  });
});

describe('accountStore saveProfile request', () => {
  it.each([
    [
      'a new name (sent trimmed) and response language',
      account(),
      draft({ name: '  Alice Muster ', response_language: 'it' }),
      { name: 'Alice Muster', response_language: 'it' },
    ],
    [
      'a response language back to the org default (null)',
      account({ response_language: 'de' }),
      draft({ response_language: null }),
      { response_language: null },
    ],
    [
      'a timezone over a stored null',
      account({ timezone: null }),
      draft({ timezone: DEFAULT_ZONE }),
      { timezone: DEFAULT_ZONE },
    ],
    [
      'cleared personal instructions (sent as typed)',
      account(),
      draft({ personal_instructions: '' }),
      { personal_instructions: '' },
    ],
    [
      'personal instructions with surrounding whitespace (never trimmed)',
      account(),
      draft({ personal_instructions: '  Keep it short.\n' }),
      { personal_instructions: '  Keep it short.\n' },
    ],
  ] as Array<[string, MyAccount, AccountDraft, Record<string, unknown>]>)(
    'PATCHes exactly the changed fields for %s',
    async (_label, saved, input, body) => {
      await signIn();
      await loadAccount(saved);
      api.patchMyAccount.mockResolvedValueOnce({ ...saved, ...body } as MyAccount);
      const store = useAccountStore();

      const result = await store.saveProfile(input);

      expect({ result, patchArgs: api.patchMyAccount.mock.calls, calls: apiCalls() }).toEqual({
        result: { ok: true },
        patchArgs: [[body]],
        calls: { ...NO_CALLS, patchMyAccount: 1 },
      });
    },
  );

  it("keeps the response, syncs the auth store's response language and adds the saved toast", async () => {
    await signIn(member({ response_language: null }));
    await loadAccount();
    const saved = account({ name: 'Alice Muster', response_language: 'it' });
    api.patchMyAccount.mockResolvedValueOnce(saved);
    const store = useAccountStore();

    const result = await store.saveProfile(draft({ name: 'Alice Muster', response_language: 'it' }));

    const auth = useAuthStore();
    expect({ result, account: store.account, me: auth.me, toasts: toastSummary() }).toEqual({
      result: { ok: true },
      account: saved,
      me: member({ response_language: 'it' }),
      toasts: [{ kind: 'success', title: t('account.toast.saved') }],
    });
  });

  it("makes the auth store's ui_language and the UI locale follow the response", async () => {
    await signIn(member({ ui_language: 'en' }));
    await loadAccount();
    // The UI language was changed on another device meanwhile; the response carries it.
    api.patchMyAccount.mockResolvedValueOnce(account({ name: 'Alice Muster', ui_language: 'fr' }));
    const store = useAccountStore();

    await store.saveProfile(draft({ name: 'Alice Muster' }));

    expect({ meUi: useAuthStore().me?.ui_language, locale: locale.value }).toEqual({ meUi: 'fr', locale: 'fr' });
  });

  it('is saving while the PATCH runs and idle after a success', async () => {
    await signIn();
    await loadAccount();
    const pending = deferred<MyAccount>();
    api.patchMyAccount.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.saveProfile(draft({ name: 'Alice Muster' }));
    await flushPromises();
    const savingWhilePending = store.saving;
    pending.resolve(account({ name: 'Alice Muster' }));
    await running;

    expect({ savingWhilePending, savingAfter: store.saving }).toEqual({ savingWhilePending: true, savingAfter: false });
  });

  it('is saving while the PATCH runs and idle after a failure', async () => {
    await signIn();
    await loadAccount();
    const pending = deferred<MyAccount>();
    api.patchMyAccount.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.saveProfile(draft({ name: 'Alice Muster' }));
    await flushPromises();
    const savingWhilePending = store.saving;
    pending.reject(new ApiError(500, 'Internal Server Error'));
    await running;

    expect({ savingWhilePending, savingAfter: store.saving }).toEqual({ savingWhilePending: true, savingAfter: false });
  });

  it.each([
    ['a 422', () => new ApiError(422, 'Unprocessable Entity', 'Invalid timezone'), 'account.error.invalid'],
    ['a 429', () => new ApiError(429, 'Too Many Requests'), 'auth.error.rateLimited'],
    ['a 500', () => new ApiError(500, 'Internal Server Error'), 'account.error.generic'],
    ['a 404', () => new ApiError(404, 'Not Found', 'Account not found'), 'account.error.generic'],
    ['a network failure', () => new TypeError('Failed to fetch'), 'account.error.generic'],
  ] as Array<[string, () => Error, string]>)(
    'maps %s to %j, keeps the account and the auth profile, adds no success toast and never throws',
    async (_label, makeError, key) => {
      await signIn(member({ response_language: null }));
      await loadAccount();
      api.patchMyAccount.mockRejectedValueOnce(makeError());
      const store = useAccountStore();

      const result = await store.saveProfile(draft({ name: 'Alice Muster', response_language: 'it' }));

      expect({
        result,
        account: store.account,
        me: useAuthStore().me,
        successToasts: toastSummary().filter((toast) => toast.kind === 'success'),
      }).toEqual({
        result: { ok: false, messageKey: key },
        account: account(),
        me: member({ response_language: null }),
        successToasts: [],
      });
    },
  );
});

// --- setUiLanguage --------------------------------------------------------

describe('accountStore setUiLanguage', () => {
  it('switches the UI locale before the PATCH resolves, then keeps it and syncs the auth store', async () => {
    await signIn(member({ ui_language: 'en' }));
    await loadAccount(account({ ui_language: 'en' }));
    const pending = deferred<MyAccount>();
    api.patchMyAccount.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.setUiLanguage('de');
    await flushPromises();
    const localeWhilePending = locale.value;
    const patchArgsWhilePending = [...api.patchMyAccount.mock.calls];
    pending.resolve(account({ ui_language: 'de' }));
    const result = await running;

    expect({
      localeWhilePending,
      patchArgsWhilePending,
      result,
      locale: locale.value,
      account: store.account,
      meUi: useAuthStore().me?.ui_language,
    }).toEqual({
      localeWhilePending: 'de',
      patchArgsWhilePending: [[{ ui_language: 'de' }]],
      result: { ok: true },
      locale: 'de',
      account: account({ ui_language: 'de' }),
      meUi: 'de',
    });
  });

  it.each([
    ['a 422', () => new ApiError(422, 'Unprocessable Entity'), 'account.error.invalid'],
    ['a 429', () => new ApiError(429, 'Too Many Requests'), 'auth.error.rateLimited'],
    ['a 500', () => new ApiError(500, 'Internal Server Error'), 'account.error.generic'],
    ['a network failure', () => new TypeError('Failed to fetch'), 'account.error.generic'],
  ] as Array<[string, () => Error, string]>)(
    'reverts to the previous locale on %s and returns %j',
    async (_label, makeError, key) => {
      await signIn(member({ ui_language: 'fr' }));
      await loadAccount(account({ ui_language: 'fr' }));
      api.patchMyAccount.mockRejectedValueOnce(makeError());
      const store = useAccountStore();

      const result = await store.setUiLanguage('de');

      expect({
        result,
        patchArgs: api.patchMyAccount.mock.calls,
        locale: locale.value,
        account: store.account,
        meUi: useAuthStore().me?.ui_language,
      }).toEqual({
        result: { ok: false, messageKey: key },
        patchArgs: [[{ ui_language: 'de' }]],
        locale: 'fr',
        account: account({ ui_language: 'fr' }),
        meUi: 'fr',
      });
    },
  );

  it('returns ok without a request when the language is already the UI locale', async () => {
    await signIn(member({ ui_language: 'de' }));
    await loadAccount(account({ ui_language: 'de' }));
    const store = useAccountStore();

    const result = await store.setUiLanguage('de');

    expect({ result, calls: apiCalls(), locale: locale.value }).toEqual({
      result: { ok: true },
      calls: NO_CALLS,
      locale: 'de',
    });
  });
});

// --- presetTimezone -------------------------------------------------------

describe('accountStore presetTimezone', () => {
  it("PATCHes the browser's zone when the stored timezone is null and keeps the response", async () => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount.mockResolvedValueOnce(account({ timezone: BROWSER_ZONE }));
    const store = useAccountStore();

    await store.presetTimezone();

    expect({ calls: apiCalls(), patchArgs: api.patchMyAccount.mock.calls, account: store.account }).toEqual({
      calls: { ...NO_CALLS, getMyAccount: 1, patchMyAccount: 1 },
      patchArgs: [[{ timezone: BROWSER_ZONE }]],
      account: account({ timezone: BROWSER_ZONE }),
    });
  });

  it('makes no PATCH when a timezone is already stored', async () => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: 'Asia/Tokyo' }));
    const store = useAccountStore();

    await store.presetTimezone();

    expect(apiCalls()).toEqual({ ...NO_CALLS, getMyAccount: 1 });
  });

  it('falls back to Europe/Zurich when the server refuses the browser zone with a 422', async () => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount
      .mockRejectedValueOnce(new ApiError(422, 'Unprocessable Entity'))
      .mockResolvedValueOnce(account({ timezone: DEFAULT_ZONE }));
    const store = useAccountStore();

    await store.presetTimezone();

    expect({ patchArgs: api.patchMyAccount.mock.calls, account: store.account }).toEqual({
      patchArgs: [[{ timezone: BROWSER_ZONE }], [{ timezone: DEFAULT_ZONE }]],
      account: account({ timezone: DEFAULT_ZONE }),
    });
  });

  it('makes no second PATCH when the refused browser zone already was Europe/Zurich', async () => {
    stubBrowserTimezone(DEFAULT_ZONE);
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount.mockRejectedValueOnce(new ApiError(422, 'Unprocessable Entity'));

    await expect(useAccountStore().presetTimezone()).resolves.toBeUndefined();
    expect(api.patchMyAccount.mock.calls).toEqual([[{ timezone: DEFAULT_ZONE }]]);
  });

  it.each([
    ['an empty zone', () => stubBrowserTimezone('')],
    [
      'a throwing Intl lookup',
      () => {
        vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockImplementation(() => {
          throw new RangeError('Unsupported time zone');
        });
      },
    ],
  ])('PATCHes Europe/Zurich when the browser reports %s', async (_label, stub) => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount.mockResolvedValueOnce(account({ timezone: DEFAULT_ZONE }));
    stub();

    await useAccountStore().presetTimezone();

    expect(api.patchMyAccount.mock.calls).toEqual([[{ timezone: DEFAULT_ZONE }]]);
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 401', () => new ApiError(401, 'Unauthorized')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])('swallows %s from GET /api/me and makes no PATCH', async (_label, makeError) => {
    await signIn();
    api.getMyAccount.mockRejectedValueOnce(makeError());

    await expect(useAccountStore().presetTimezone()).resolves.toBeUndefined();
    expect(apiCalls()).toEqual({ ...NO_CALLS, getMyAccount: 1 });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 429', () => new ApiError(429, 'Too Many Requests')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])('swallows %s from the PATCH and makes no fallback PATCH (only a 422 falls back)', async (_label, makeError) => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount.mockRejectedValueOnce(makeError());

    await expect(useAccountStore().presetTimezone()).resolves.toBeUndefined();
    expect(api.patchMyAccount.mock.calls).toEqual([[{ timezone: BROWSER_ZONE }]]);
  });

  it('swallows a failing fallback PATCH too', async () => {
    await signIn();
    api.getMyAccount.mockResolvedValueOnce(account({ timezone: null }));
    api.patchMyAccount
      .mockRejectedValueOnce(new ApiError(422, 'Unprocessable Entity'))
      .mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));

    await expect(useAccountStore().presetTimezone()).resolves.toBeUndefined();
    expect(api.patchMyAccount.mock.calls).toEqual([[{ timezone: BROWSER_ZONE }], [{ timezone: DEFAULT_ZONE }]]);
  });

  it('runs once per user: a second call for the same user makes no request', async () => {
    await signIn();
    api.getMyAccount.mockResolvedValue(account({ timezone: null }));
    api.patchMyAccount.mockResolvedValue(account({ timezone: BROWSER_ZONE }));
    const store = useAccountStore();

    await store.presetTimezone();
    await store.presetTimezone();

    expect(apiCalls()).toEqual({ ...NO_CALLS, getMyAccount: 1, patchMyAccount: 1 });
  });

  it('runs once per user even for two calls made back to back', async () => {
    await signIn();
    api.getMyAccount.mockResolvedValue(account({ timezone: DEFAULT_ZONE }));
    const store = useAccountStore();

    await Promise.all([store.presetTimezone(), store.presetTimezone()]);

    expect(apiCalls()).toEqual({ ...NO_CALLS, getMyAccount: 1 });
  });

  it('runs at most once per user even when the first attempt failed', async () => {
    await signIn();
    api.getMyAccount.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    api.getMyAccount.mockResolvedValue(account({ timezone: null }));
    api.patchMyAccount.mockResolvedValue(account({ timezone: BROWSER_ZONE }));
    const store = useAccountStore();

    await store.presetTimezone();
    await store.presetTimezone();

    expect(apiCalls()).toEqual({ ...NO_CALLS, getMyAccount: 1 });
  });

  it('runs again for a different signed-in user, but never twice for the same one', async () => {
    await signIn(member({ user_id: ALICE_ID }));
    api.getMyAccount.mockResolvedValue(account({ timezone: DEFAULT_ZONE }));
    const store = useAccountStore();
    const auth = useAuthStore();

    await store.presetTimezone();
    auth.me = member({ user_id: BOB_ID });
    await store.presetTimezone();
    const afterBob = api.getMyAccount.mock.calls.length;
    await store.presetTimezone();
    auth.me = member({ user_id: ALICE_ID });
    await store.presetTimezone();

    expect({ afterBob, total: api.getMyAccount.mock.calls.length }).toEqual({ afterBob: 2, total: 2 });
  });
});

// --- changePassword -------------------------------------------------------

describe('accountStore changePassword client-side checks', () => {
  it.each([
    ['a too-short new password', 'short-pw', 'short-pw', 'auth.password.error.tooShort'],
    ['a confirmation that differs', NEW_PASSWORD, `${NEW_PASSWORD}!`, 'auth.password.error.mismatch'],
    ['the email as the new password', 'Alice@Example.CH', 'Alice@Example.CH', 'auth.password.error.equalsEmail'],
    ['a too-short and mismatched new password (first issue wins)', 'short-pw', 'other', 'auth.password.error.tooShort'],
  ])('refuses %s with %j and makes no request', async (_label, next, confirm, key) => {
    await signIn();
    const store = useAccountStore();

    const result = await store.changePassword(CURRENT_PASSWORD, next, confirm, EMAIL);

    expect({ result, calls: apiCalls(), me: useAuthStore().me }).toEqual({
      result: { ok: false, messageKey: key },
      calls: NO_CALLS,
      me: member(),
    });
  });

  it("refuses a blank current password with 'account.password.error.currentRequired' and makes no request", async () => {
    await signIn();
    const store = useAccountStore();

    const result = await store.changePassword('', NEW_PASSWORD, NEW_PASSWORD, EMAIL);

    expect({ result, calls: apiCalls() }).toEqual({
      result: { ok: false, messageKey: 'account.password.error.currentRequired' },
      calls: NO_CALLS,
    });
  });
});

describe('accountStore changePassword request', () => {
  it('POSTs both passwords, then forgets the session locally without the logout API or a session-expired toast', async () => {
    stubBrowserLanguages(['de-CH']);
    await signIn(member({ ui_language: 'fr' }));
    await loadAccount(account({ ui_language: 'fr' }));
    seedThread();
    api.changeMyPassword.mockResolvedValueOnce(undefined);
    const store = useAccountStore();

    const result = await store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);

    const auth = useAuthStore();
    expect({
      result,
      changeArgs: api.changeMyPassword.mock.calls,
      me: auth.me,
      loaded: auth.loaded,
      isAuthenticated: auth.isAuthenticated,
      thread: useChatStore().thread,
      locale: locale.value,
      logoutCalls: mockedLogout.mock.calls.length,
      expiredToasts: toastSummary().filter((toast) => toast.title === t('auth.sessionExpired.title')),
      account: store.account,
    }).toEqual({
      result: { ok: true },
      changeArgs: [[CURRENT_PASSWORD, NEW_PASSWORD]],
      me: null,
      loaded: true,
      isAuthenticated: false,
      thread: [],
      locale: 'de',
      logoutCalls: 0,
      expiredToasts: [],
      account: null,
    });
  });

  it("maps a 403 to 'account.password.error.current' and keeps the user signed in", async () => {
    await signIn();
    await loadAccount();
    seedThread();
    api.changeMyPassword.mockRejectedValueOnce(new ApiError(403, 'Forbidden', 'Re-authentication failed.'));
    const store = useAccountStore();

    const result = await store.changePassword('Wrong-Password-0000', NEW_PASSWORD, NEW_PASSWORD, EMAIL);

    const auth = useAuthStore();
    expect({
      result,
      me: auth.me,
      isAuthenticated: auth.isAuthenticated,
      threadLength: useChatStore().thread.length,
      account: store.account,
      logoutCalls: mockedLogout.mock.calls.length,
    }).toEqual({
      result: { ok: false, messageKey: 'account.password.error.current' },
      me: member(),
      isAuthenticated: true,
      threadLength: 1,
      account: account(),
      logoutCalls: 0,
    });
  });

  it.each([
    ['too_short', 'auth.password.error.tooShort'],
    ['too_long', 'auth.password.error.tooLong'],
    ['common', 'auth.password.error.common'],
    ['equals_email', 'auth.password.error.equalsEmail'],
    [undefined, 'auth.password.error.generic'],
  ])('maps a 422 with reason %j to %j and keeps the user signed in', async (reason, key) => {
    await signIn();
    api.changeMyPassword.mockRejectedValueOnce(
      new ApiError(422, 'Unprocessable Entity', 'Password does not meet the policy.', reason),
    );

    const result = await useAccountStore().changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);

    expect({ result, me: useAuthStore().me }).toEqual({ result: { ok: false, messageKey: key }, me: member() });
  });

  it.each([
    ['a 429', () => new ApiError(429, 'Too Many Requests'), 'auth.error.rateLimited'],
    ['a 500', () => new ApiError(500, 'Internal Server Error'), 'auth.error.generic'],
    ['a 401', () => new ApiError(401, 'Unauthorized'), 'auth.error.generic'],
    ['a network failure', () => new TypeError('Failed to fetch'), 'auth.error.generic'],
  ] as Array<[string, () => Error, string]>)('maps %s to %j and never throws', async (_label, makeError, key) => {
    await signIn();
    api.changeMyPassword.mockRejectedValueOnce(makeError());

    const result = await useAccountStore().changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);

    expect({ result, logoutCalls: mockedLogout.mock.calls.length }).toEqual({
      result: { ok: false, messageKey: key },
      logoutCalls: 0,
    });
  });

  it('is changingPassword while the POST runs and idle after a success', async () => {
    await signIn();
    const pending = deferred<undefined>();
    api.changeMyPassword.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);
    await flushPromises();
    const busyWhilePending = store.changingPassword;
    pending.resolve(undefined);
    await running;

    expect({ busyWhilePending, busyAfter: store.changingPassword }).toEqual({
      busyWhilePending: true,
      busyAfter: false,
    });
  });

  it('is changingPassword while the POST runs and idle after a failure', async () => {
    await signIn();
    const pending = deferred<undefined>();
    api.changeMyPassword.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);
    await flushPromises();
    const busyWhilePending = store.changingPassword;
    pending.reject(new ApiError(403, 'Forbidden'));
    await running;

    expect({ busyWhilePending, busyAfter: store.changingPassword }).toEqual({
      busyWhilePending: true,
      busyAfter: false,
    });
  });

  it('never keeps either password in any store state or web storage while the POST runs', async () => {
    await signIn();
    await loadAccount();
    const pending = deferred<undefined>();
    api.changeMyPassword.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);
    await flushPromises();
    const keptWhilePending = passwordsKept();
    pending.resolve(undefined);
    const result = await running;

    expect({ keptWhilePending, posted: api.changeMyPassword.mock.calls.length, result }).toEqual({
      keptWhilePending: NOTHING_KEPT,
      posted: 1,
      result: { ok: true },
    });
  });

  it.each([
    ['a 403', () => new ApiError(403, 'Forbidden', 'Re-authentication failed.'), 'account.password.error.current'],
    ['a 422', () => new ApiError(422, 'Unprocessable Entity', 'Too common.', 'common'), 'auth.password.error.common'],
    ['a 500', () => new ApiError(500, 'Internal Server Error'), 'auth.error.generic'],
  ] as Array<[string, () => Error, string]>)(
    'never keeps either password in any store state or web storage after %s',
    async (_label, makeError, key) => {
      await signIn();
      await loadAccount();
      api.changeMyPassword.mockRejectedValueOnce(makeError());
      const store = useAccountStore();

      const result = await store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, NEW_PASSWORD, EMAIL);

      expect({ result, kept: passwordsKept(), posted: api.changeMyPassword.mock.calls.length }).toEqual({
        result: { ok: false, messageKey: key },
        kept: NOTHING_KEPT,
        posted: 1,
      });
    },
  );

  it('never keeps either password after a refused (client-side) attempt', async () => {
    await signIn();
    await loadAccount();
    const store = useAccountStore();

    const result = await store.changePassword(CURRENT_PASSWORD, NEW_PASSWORD, `${NEW_PASSWORD}?`, EMAIL);

    expect({ result, kept: passwordsKept() }).toEqual({
      result: { ok: false, messageKey: 'auth.password.error.mismatch' },
      kept: NOTHING_KEPT,
    });
  });
});

// --- Sessions -------------------------------------------------------------

describe('accountStore loadSessions', () => {
  it('keeps the sessions with the current one first, then by last seen (newest first)', async () => {
    api.listMySessions.mockResolvedValueOnce([LAPTOP, CURRENT, PHONE]);
    const store = useAccountStore();

    await store.loadSessions();

    expect({ calls: apiCalls(), sessions: store.sessions, sessionsError: store.sessionsError }).toEqual({
      calls: { ...NO_CALLS, listMySessions: 1 },
      sessions: SORTED_SESSIONS,
      sessionsError: null,
    });
  });

  it('is sessionsLoading while the request runs and idle afterwards', async () => {
    const pending = deferred<SessionSummary[]>();
    api.listMySessions.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.loadSessions();
    const loadingWhilePending = store.sessionsLoading;
    pending.resolve([CURRENT]);
    await running;

    expect({ loadingWhilePending, loadingAfter: store.sessionsLoading }).toEqual({
      loadingWhilePending: true,
      loadingAfter: false,
    });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 429', () => new ApiError(429, 'Too Many Requests')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])("sets sessionsError 'account.sessions.error.load' on %s and never throws", async (_label, makeError) => {
    api.listMySessions.mockRejectedValueOnce(makeError());
    const store = useAccountStore();

    await expect(store.loadSessions()).resolves.toBeUndefined();
    expect({ sessionsError: store.sessionsError, sessionsLoading: store.sessionsLoading }).toEqual({
      sessionsError: 'account.sessions.error.load',
      sessionsLoading: false,
    });
  });

  it('clears an earlier sessionsError on a successful reload', async () => {
    const store = useAccountStore();
    api.listMySessions.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    await store.loadSessions();
    api.listMySessions.mockResolvedValueOnce([PHONE, CURRENT]);

    await store.loadSessions();

    expect({ sessionsError: store.sessionsError, sessions: store.sessions }).toEqual({
      sessionsError: null,
      sessions: [CURRENT, PHONE],
    });
  });
});

describe('accountStore revokeSession', () => {
  it('sets revokingId while the DELETE runs and clears it afterwards', async () => {
    await signIn();
    await loadSessions();
    const pending = deferred<undefined>();
    api.revokeMySession.mockReturnValueOnce(pending.promise);
    const store = useAccountStore();

    const running = store.revokeSession(PHONE_SESSION_ID);
    await flushPromises();
    const revokingWhilePending = store.revokingId;
    pending.resolve(undefined);
    await running;

    expect({ revokingWhilePending, revokingAfter: store.revokingId }).toEqual({
      revokingWhilePending: PHONE_SESSION_ID,
      revokingAfter: null,
    });
  });

  it.each([
    ['a success', () => api.revokeMySession.mockResolvedValueOnce(undefined)],
    ['a 404 (already gone)', () => api.revokeMySession.mockRejectedValueOnce(new ApiError(404, 'Not Found'))],
  ])('removes another session from the list on %s and keeps the user signed in', async (_label, arrange) => {
    await signIn();
    await loadSessions();
    arrange();
    const store = useAccountStore();

    const result = await store.revokeSession(PHONE_SESSION_ID);

    expect({
      ok: result.ok,
      endedCurrent: result.endedCurrent ?? false,
      revokeArgs: api.revokeMySession.mock.calls,
      sessions: store.sessions,
      me: useAuthStore().me,
      logoutCalls: mockedLogout.mock.calls.length,
    }).toEqual({
      ok: true,
      endedCurrent: false,
      revokeArgs: [[PHONE_SESSION_ID]],
      sessions: [CURRENT, LAPTOP],
      me: member(),
      logoutCalls: 0,
    });
  });

  it('ends the local session (no logout API call) when the current session is revoked', async () => {
    stubBrowserLanguages(['fr-CH']);
    await signIn(member({ ui_language: 'de' }));
    await loadAccount(account({ ui_language: 'de' }));
    await loadSessions();
    seedThread();
    api.revokeMySession.mockResolvedValueOnce(undefined);
    const store = useAccountStore();

    const result = await store.revokeSession(CURRENT_SESSION_ID);

    const auth = useAuthStore();
    expect({
      result,
      revokeArgs: api.revokeMySession.mock.calls,
      me: auth.me,
      loaded: auth.loaded,
      thread: useChatStore().thread,
      locale: locale.value,
      logoutCalls: mockedLogout.mock.calls.length,
      expiredToasts: toastSummary().filter((toast) => toast.title === t('auth.sessionExpired.title')),
      account: store.account,
    }).toEqual({
      result: { ok: true, endedCurrent: true },
      revokeArgs: [[CURRENT_SESSION_ID]],
      me: null,
      loaded: true,
      thread: [],
      locale: 'fr',
      logoutCalls: 0,
      expiredToasts: [],
      account: null,
    });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 403', () => new ApiError(403, 'Forbidden')],
    ['a 429', () => new ApiError(429, 'Too Many Requests')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])("returns 'account.sessions.error.revoke' on %s and keeps the list", async (_label, makeError) => {
    await signIn();
    await loadSessions();
    api.revokeMySession.mockRejectedValueOnce(makeError());
    const store = useAccountStore();

    const result = await store.revokeSession(PHONE_SESSION_ID);

    expect({
      result,
      sessions: store.sessions,
      revokingId: store.revokingId,
      me: useAuthStore().me,
    }).toEqual({
      result: { ok: false, messageKey: 'account.sessions.error.revoke' },
      sessions: SORTED_SESSIONS,
      revokingId: null,
      me: member(),
    });
  });
});

// --- reset and the auth store ----------------------------------------------

describe('accountStore reset', () => {
  it('clears the account, the sessions and every error and flag', async () => {
    await signIn();
    await loadAccount();
    await loadSessions();
    api.getMyAccount.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'));
    const store = useAccountStore();
    await store.load();
    const before = { account: store.account, loadError: store.loadError, sessions: store.sessions.length };

    store.reset();

    expect({
      before,
      after: {
        account: store.account,
        loading: store.loading,
        saving: store.saving,
        loadError: store.loadError,
        sessions: store.sessions,
        sessionsLoading: store.sessionsLoading,
        sessionsError: store.sessionsError,
        revokingId: store.revokingId,
        changingPassword: store.changingPassword,
      },
    }).toEqual({
      before: { account: account(), loadError: 'account.error.load', sessions: 3 },
      after: {
        account: null,
        loading: false,
        saving: false,
        loadError: null,
        sessions: [],
        sessionsLoading: false,
        sessionsError: null,
        revokingId: null,
        changingPassword: false,
      },
    });
  });

  it("is reset by the auth store's logout()", async () => {
    await signIn();
    await loadAccount();
    await loadSessions();
    mockedLogout.mockResolvedValueOnce(undefined);
    const store = useAccountStore();

    await useAuthStore().logout();

    expect({ account: store.account, sessions: store.sessions, logoutCalls: mockedLogout.mock.calls.length }).toEqual({
      account: null,
      sessions: [],
      logoutCalls: 1,
    });
  });

  it("is reset by the auth store's forgetSession()", async () => {
    await signIn();
    await loadAccount();
    await loadSessions();
    const store = useAccountStore();

    useAuthStore().forgetSession();
    await flushPromises();

    expect({ account: store.account, sessions: store.sessions, logoutCalls: mockedLogout.mock.calls.length }).toEqual({
      account: null,
      sessions: [],
      logoutCalls: 0,
    });
  });
});
