/**
 * Auth store tests (issue #155: auth pages and role-aware app shell).
 *
 * `useAuthStore` (Pinia setup store) owns who is logged in:
 *
 * - `me` (the `GET /api/auth/me` payload or `null`), `loaded`, `role`
 *   (`shellRole(me)`, fail closed) and `isAuthenticated` (`role !== null`).
 * - `ensureLoaded()`: fetches `/api/auth/me` once per app load (concurrent
 *   callers share the request, later calls reuse it). Signed in: the UI
 *   language follows the profile's `ui_language`. A 401: logged out, and the
 *   UI language follows the browser (`browserLocale()`). Any other error:
 *   logged out (fail closed). Never throws.
 * - `login(email, password)`: `'ok' | 'invalid' | 'rate_limited' | 'error'`,
 *   never throws, never keeps the password.
 * - `loadMe()`: reloads the profile (after accepting an invitation, whose 204
 *   sets the session cookie).
 * - `logout()`: ends the session (a failing call is swallowed), forgets the
 *   user, clears the chat thread and returns to the browser's language.
 * - `handleUnauthorized()`: called by the global 401 handler. The first 401
 *   of a signed-in session adds one session-expired toast (in the user's
 *   language) and forgets the user; later 401s add nothing.
 * - The chat thread is cleared when a different user signs in after an
 *   expiry; the same user signing back in keeps it.
 *
 * `@/api/auth` is mocked; error cases use the real `ApiError` class.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { getMe, login as apiLogin, logout as apiLogout } from '@/api/auth';
import { ApiError } from '@/api/client';
import { locale, setLocale, t } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { useAuthStore } from '@/stores/auth';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';
import type { MeResponse, ThreadItem } from '@/api/types';

vi.mock('@/api/auth', () => ({
  login: vi.fn(),
  logout: vi.fn(),
  getMe: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  getInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

const mockedGetMe = vi.mocked(getMe);
const mockedLogin = vi.mocked(apiLogin);
const mockedLogout = vi.mocked(apiLogout);

const ORG_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';
const ALICE_ID = '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90';
const BOB_ID = '3c8d1f7a-9e2b-4a6c-8d5f-0e1a2b3c4d5e';
const EMAIL = 'alice@example.ch';
const PASSWORD = 'Plumbago-Lantern-4417';

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

function superAdmin(): MeResponse {
  return {
    user_id: '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f',
    kind: 'super_admin',
    org_id: null,
    role: null,
    ui_language: 'fr',
    response_language: null,
  };
}

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

function stubBrowserLanguages(languages: readonly string[]): void {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(languages);
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(languages[0] ?? '');
}

/** Puts one user message into the chat thread, so a test can see whether it is cleared. */
function seedThread(): void {
  const item: ThreadItem = {
    type: 'message',
    data: { id: 'm-seed', role: 'user', content: 'What is on my calendar?', timestamp: new Date() },
  };
  useChatStore().thread.push(item);
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

/** Everything the store and the browser storage keep, as one string for leak checks. */
function everythingKept(): string {
  return JSON.stringify([useAuthStore().$state, storageDump(localStorage), storageDump(sessionStorage)]);
}

function threadIds(): string[] {
  return useChatStore().thread.map((item) => item.data.id);
}

/** Signs in through `login` as `me` (both API calls succeed). */
async function signInAs(me: MeResponse): Promise<void> {
  mockedLogin.mockResolvedValueOnce(undefined);
  mockedGetMe.mockResolvedValueOnce(me);
  const outcome = await useAuthStore().login(EMAIL, PASSWORD);
  if (outcome !== 'ok') throw new Error(`test setup: expected login to succeed, got ${outcome}`);
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  setActivePinia(createPinia());
  mockedGetMe.mockReset();
  mockedLogin.mockReset();
  mockedLogout.mockReset();
  setLocale('en');
  stubBrowserLanguages(['en-US']);
});

afterEach(() => {
  setLocale('en');
});

// --- Initial state --------------------------------------------------------

describe('authStore initial state', () => {
  it('starts logged out and not loaded', () => {
    const auth = useAuthStore();

    expect({
      me: auth.me,
      loaded: auth.loaded,
      role: auth.role,
      isAuthenticated: auth.isAuthenticated,
    }).toEqual({ me: null, loaded: false, role: null, isAuthenticated: false });
  });
});

// --- ensureLoaded ---------------------------------------------------------

describe('authStore ensureLoaded', () => {
  it('fetches /api/auth/me once and keeps the profile', async () => {
    const me = member({ role: 'org_admin' });
    mockedGetMe.mockResolvedValueOnce(me);
    const auth = useAuthStore();

    await auth.ensureLoaded();

    expect({
      calls: mockedGetMe.mock.calls.length,
      me: auth.me,
      loaded: auth.loaded,
      role: auth.role,
      isAuthenticated: auth.isAuthenticated,
    }).toEqual({ calls: 1, me, loaded: true, role: 'org_admin', isAuthenticated: true });
  });

  it('shares one in-flight request between concurrent callers', async () => {
    const pending = deferred<MeResponse>();
    mockedGetMe.mockReturnValueOnce(pending.promise);
    const auth = useAuthStore();

    const first = auth.ensureLoaded();
    const second = auth.ensureLoaded();
    const third = auth.ensureLoaded();
    const callsWhilePending = mockedGetMe.mock.calls.length;
    pending.resolve(member());
    await Promise.all([first, second, third]);

    expect({ callsWhilePending, calls: mockedGetMe.mock.calls.length, role: auth.role }).toEqual({
      callsWhilePending: 1,
      calls: 1,
      role: 'editor',
    });
  });

  it('does not refetch on later calls', async () => {
    mockedGetMe.mockResolvedValue(member());
    const auth = useAuthStore();

    await auth.ensureLoaded();
    await auth.ensureLoaded();
    await auth.ensureLoaded();

    expect(mockedGetMe).toHaveBeenCalledTimes(1);
  });

  it('does not refetch on later calls after a 401 either', async () => {
    mockedGetMe.mockRejectedValue(new ApiError(401, 'Unauthorized'));
    const auth = useAuthStore();

    await auth.ensureLoaded();
    await auth.ensureLoaded();

    expect(mockedGetMe).toHaveBeenCalledTimes(1);
  });

  it.each(['de', 'fr', 'en'] as const)("switches the UI language to the profile's ui_language %s", async (lang) => {
    stubBrowserLanguages(lang === 'de' ? ['fr-CH'] : ['de-CH']);
    mockedGetMe.mockResolvedValueOnce(member({ ui_language: lang }));

    await useAuthStore().ensureLoaded();

    expect(locale.value).toBe(lang);
  });

  it('reports a Super Admin as the super_admin role', async () => {
    mockedGetMe.mockResolvedValueOnce(superAdmin());
    const auth = useAuthStore();

    await auth.ensureLoaded();

    expect({ role: auth.role, isAuthenticated: auth.isAuthenticated }).toEqual({
      role: 'super_admin',
      isAuthenticated: true,
    });
  });

  it("is logged out after a 401 and follows the browser's language", async () => {
    stubBrowserLanguages(['fr-CH', 'de']);
    mockedGetMe.mockRejectedValueOnce(new ApiError(401, 'Unauthorized'));
    const auth = useAuthStore();

    await auth.ensureLoaded();

    expect({ me: auth.me, loaded: auth.loaded, isAuthenticated: auth.isAuthenticated, locale: locale.value }).toEqual(
      { me: null, loaded: true, isAuthenticated: false, locale: 'fr' },
    );
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 403', () => new ApiError(403, 'Forbidden')],
    ['a network failure', () => new TypeError('Failed to fetch')],
    ['a non-Error rejection', () => 'boom' as unknown as Error],
  ])('fails closed (logged out, loaded) on %s and never throws', async (_label, makeError) => {
    mockedGetMe.mockRejectedValueOnce(makeError());
    const auth = useAuthStore();

    await expect(auth.ensureLoaded()).resolves.toBeUndefined();
    expect({ me: auth.me, loaded: auth.loaded, isAuthenticated: auth.isAuthenticated }).toEqual({
      me: null,
      loaded: true,
      isAuthenticated: false,
    });
  });

  it.each([
    ['a Super Admin with an org', { ...superAdmin(), org_id: ORG_ID }],
    ['a member without a role', member({ role: null })],
    ['a member without an org', member({ org_id: null })],
    ['an unknown role', { ...member(), role: 'owner' }],
  ] as Array<[string, MeResponse]>)('never authenticates a malformed profile (%s)', async (_label, me) => {
    mockedGetMe.mockResolvedValueOnce(me);
    const auth = useAuthStore();

    await auth.ensureLoaded();

    expect({ role: auth.role, isAuthenticated: auth.isAuthenticated }).toEqual({
      role: null,
      isAuthenticated: false,
    });
  });
});

// --- login ----------------------------------------------------------------

describe('authStore login', () => {
  it("calls the login API with the email and password, then loads the profile: 'ok'", async () => {
    const me = member({ ui_language: 'fr' });
    mockedLogin.mockResolvedValueOnce(undefined);
    mockedGetMe.mockResolvedValueOnce(me);
    const auth = useAuthStore();

    const outcome = await auth.login(EMAIL, PASSWORD);

    expect({
      outcome,
      loginArgs: mockedLogin.mock.calls,
      loginBeforeMe: mockedLogin.mock.invocationCallOrder[0] < mockedGetMe.mock.invocationCallOrder[0],
      me: auth.me,
      isAuthenticated: auth.isAuthenticated,
      locale: locale.value,
    }).toEqual({
      outcome: 'ok',
      loginArgs: [[EMAIL, PASSWORD]],
      loginBeforeMe: true,
      me,
      isAuthenticated: true,
      locale: 'fr',
    });
  });

  it.each([
    ['a 401 (wrong email or password)', () => new ApiError(401, 'Unauthorized', 'Invalid email or password'), 'invalid'],
    ['a 429', () => new ApiError(429, 'Too Many Requests'), 'rate_limited'],
    ['a 500', () => new ApiError(500, 'Internal Server Error'), 'error'],
    ['a 403', () => new ApiError(403, 'Forbidden', 'Cross-origin request refused'), 'error'],
    ['a network failure', () => new TypeError('Failed to fetch'), 'error'],
  ] as Array<[string, () => Error, string]>)('maps %s to %j, stays logged out and never throws', async (_label, makeError, expected) => {
    mockedLogin.mockRejectedValueOnce(makeError());
    const auth = useAuthStore();

    const outcome = await auth.login(EMAIL, PASSWORD);

    expect({ outcome, me: auth.me, isAuthenticated: auth.isAuthenticated }).toEqual({
      outcome: expected,
      me: null,
      isAuthenticated: false,
    });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a 401', () => new ApiError(401, 'Unauthorized')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])("gives 'error' when the login succeeds but loading the profile fails with %s", async (_label, makeError) => {
    mockedLogin.mockResolvedValueOnce(undefined);
    mockedGetMe.mockRejectedValueOnce(makeError());
    const auth = useAuthStore();

    const outcome = await auth.login(EMAIL, PASSWORD);

    expect({ outcome, me: auth.me, isAuthenticated: auth.isAuthenticated }).toEqual({
      outcome: 'error',
      me: null,
      isAuthenticated: false,
    });
  });

  it('never keeps the password in the store state or in web storage after a successful login', async () => {
    await signInAs(member());

    expect(everythingKept()).not.toContain(PASSWORD);
  });

  it('never keeps the password in the store state or in web storage after a failed login', async () => {
    mockedLogin.mockRejectedValueOnce(new ApiError(401, 'Unauthorized'));

    await useAuthStore().login(EMAIL, PASSWORD);

    expect(everythingKept()).not.toContain(PASSWORD);
  });

  it('authenticates after an earlier 401 from ensureLoaded', async () => {
    mockedGetMe.mockRejectedValueOnce(new ApiError(401, 'Unauthorized'));
    const auth = useAuthStore();
    await auth.ensureLoaded();

    await signInAs(member({ role: 'viewer' }));

    expect({ role: auth.role, isAuthenticated: auth.isAuthenticated }).toEqual({
      role: 'viewer',
      isAuthenticated: true,
    });
  });
});

// --- loadMe ---------------------------------------------------------------

describe('authStore loadMe', () => {
  it("loads the profile, follows its ui_language and returns true", async () => {
    const me = member({ role: 'viewer', ui_language: 'de' });
    mockedGetMe.mockResolvedValueOnce(me);
    const auth = useAuthStore();

    const ok = await auth.loadMe();

    expect({ ok, me: auth.me, role: auth.role, locale: locale.value }).toEqual({
      ok: true,
      me,
      role: 'viewer',
      locale: 'de',
    });
  });

  it.each([
    ['a 401', () => new ApiError(401, 'Unauthorized')],
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])('returns false and forgets the user on %s', async (_label, makeError) => {
    await signInAs(member());
    mockedGetMe.mockRejectedValueOnce(makeError());
    const auth = useAuthStore();

    const ok = await auth.loadMe();

    expect({ ok, me: auth.me, isAuthenticated: auth.isAuthenticated }).toEqual({
      ok: false,
      me: null,
      isAuthenticated: false,
    });
  });
});

// --- logout ---------------------------------------------------------------

describe('authStore logout', () => {
  it("ends the session, forgets the user, clears the chat and returns to the browser's language", async () => {
    stubBrowserLanguages(['de-CH']);
    await signInAs(member({ ui_language: 'fr' }));
    seedThread();
    mockedLogout.mockResolvedValueOnce(undefined);
    const auth = useAuthStore();

    await auth.logout();

    expect({
      logoutCalls: mockedLogout.mock.calls.length,
      me: auth.me,
      isAuthenticated: auth.isAuthenticated,
      thread: useChatStore().thread,
      locale: locale.value,
    }).toEqual({ logoutCalls: 1, me: null, isAuthenticated: false, thread: [], locale: 'de' });
  });

  it.each([
    ['a 401 (session already gone)', () => new ApiError(401, 'Unauthorized')],
    ['a 500', () => new ApiError(500, 'Internal Server Error')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ])('swallows %s from the logout call and still logs out locally', async (_label, makeError) => {
    await signInAs(member());
    seedThread();
    mockedLogout.mockRejectedValueOnce(makeError());
    const auth = useAuthStore();

    await expect(auth.logout()).resolves.toBeUndefined();
    expect({ me: auth.me, isAuthenticated: auth.isAuthenticated, thread: useChatStore().thread }).toEqual({
      me: null,
      isAuthenticated: false,
      thread: [],
    });
  });
});

// --- handleUnauthorized ---------------------------------------------------

describe('authStore handleUnauthorized', () => {
  it('adds one session-expired warning toast, forgets the user and returns true', async () => {
    await signInAs(member());
    const auth = useAuthStore();

    const handled = auth.handleUnauthorized();

    const toasts = useToastStore().toasts.map(({ kind, title, body }) => ({ kind, title, body }));
    expect({ handled, me: auth.me, isAuthenticated: auth.isAuthenticated, toasts }).toEqual({
      handled: true,
      me: null,
      isAuthenticated: false,
      toasts: [
        { kind: 'warning', title: t('auth.sessionExpired.title'), body: t('auth.sessionExpired.body') },
      ],
    });
  });

  it("words the toast in the user's language at that moment", async () => {
    await signInAs(member({ ui_language: 'de' }));
    const catalog = de as Record<string, unknown>;

    useAuthStore().handleUnauthorized();

    const toast = useToastStore().toasts[0];
    expect({ title: toast?.title, body: toast?.body }).toEqual({
      title: catalog['auth.sessionExpired.title'],
      body: catalog['auth.sessionExpired.body'],
    });
  });

  it('adds no toast and returns false when nobody is logged in', () => {
    const handled = useAuthStore().handleUnauthorized();

    expect({ handled, toasts: useToastStore().toasts }).toEqual({ handled: false, toasts: [] });
  });

  it('adds only one toast for a burst of 401s', async () => {
    await signInAs(member());
    const auth = useAuthStore();

    const results = [auth.handleUnauthorized(), auth.handleUnauthorized(), auth.handleUnauthorized()];

    expect({ results, toasts: useToastStore().toasts.length }).toEqual({ results: [true, false, false], toasts: 1 });
  });

  it('keeps the chat thread, so the same user can pick up where they left off', async () => {
    await signInAs(member());
    seedThread();

    useAuthStore().handleUnauthorized();

    expect(threadIds()).toEqual(['m-seed']);
  });
});

// --- Same or different user after an expiry ------------------------------

describe('authStore user switch after an expiry', () => {
  it('keeps the chat thread when the same user logs back in after a 401', async () => {
    await signInAs(member());
    seedThread();
    useAuthStore().handleUnauthorized();

    await signInAs(member());

    expect(threadIds()).toEqual(['m-seed']);
  });

  it('clears the chat thread when a different user logs in after a 401', async () => {
    await signInAs(member());
    seedThread();
    useAuthStore().handleUnauthorized();

    await signInAs(member({ user_id: BOB_ID }));

    expect(useChatStore().thread).toEqual([]);
  });

  it('clears the chat thread when loadMe resolves a different user after a 401', async () => {
    mockedGetMe.mockResolvedValueOnce(member());
    await useAuthStore().ensureLoaded();
    seedThread();
    useAuthStore().handleUnauthorized();
    mockedGetMe.mockResolvedValueOnce(member({ user_id: BOB_ID, role: 'viewer' }));

    await useAuthStore().loadMe();

    expect({ thread: useChatStore().thread, role: useAuthStore().role }).toEqual({ thread: [], role: 'viewer' });
  });

  it('keeps the chat thread when loadMe resolves the same user after a 401', async () => {
    mockedGetMe.mockResolvedValueOnce(member());
    await useAuthStore().ensureLoaded();
    seedThread();
    useAuthStore().handleUnauthorized();
    mockedGetMe.mockResolvedValueOnce(member());

    await useAuthStore().loadMe();

    expect({ thread: threadIds(), authenticated: useAuthStore().isAuthenticated }).toEqual({
      thread: ['m-seed'],
      authenticated: true,
    });
  });
});
