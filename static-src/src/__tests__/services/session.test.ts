/**
 * Global 401 redirect tests (issue #155: "a 401 from any call redirects to
 * login and preserves the target route; a session-expired toast").
 *
 * `installUnauthorizedRedirect(router)` registers the API client's
 * unauthorized handler (`setUnauthorizedHandler`). On a 401 from any
 * non-auth endpoint it calls the auth store's `handleUnauthorized()` (one
 * session-expired toast, user forgotten) and, unless the current route is a
 * public page, navigates to `/login?redirect=<current full path>` (the query
 * is dropped when the path is not a safe redirect target).
 *
 * The test drives the real `fetchJson` against a stubbed `fetch`, a real
 * router on a memory history (`createAppRouter`) and a real auth store; only
 * `@/api/auth` is mocked (the user is an Editor). No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createMemoryHistory, type Router } from 'vue-router';
import { createPinia, setActivePinia } from 'pinia';
import { getMe } from '@/api/auth';
import { ApiError, fetchJson, setUnauthorizedHandler } from '@/api/client';
import { setLocale, t } from '@/i18n';
import { createAppRouter } from '@/router';
import { installUnauthorizedRedirect } from '@/services/session';
import { useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toasts';
import type { MeResponse } from '@/api/types';

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
const fetchMock = vi.fn<typeof fetch>();

const EDITOR: MeResponse = {
  user_id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
  kind: 'member',
  org_id: '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71',
  role: 'editor',
  ui_language: 'en',
  response_language: null,
};

function unauthorized(): Response {
  return new Response(JSON.stringify({ detail: 'Unauthorized' }), {
    status: 401,
    statusText: 'Unauthorized',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Lets pending navigations and promise callbacks run. */
async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/** A memory router with an Editor signed in, already on `path`, with the redirect installed. */
async function editorOn(path: string): Promise<Router> {
  mockedGetMe.mockResolvedValue(EDITOR);
  const router = createAppRouter(createMemoryHistory());
  await router.push(path);
  if (router.currentRoute.value.path !== path.split('?')[0]) {
    throw new Error(`test setup: expected to be on ${path}, got ${router.currentRoute.value.fullPath}`);
  }
  installUnauthorizedRedirect(router);
  return router;
}

function sessionExpiredToasts(): number {
  const title = t('auth.sessionExpired.title');
  return useToastStore().toasts.filter((toast) => toast.kind === 'warning' && toast.title === title).length;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  mockedGetMe.mockReset();
  fetchMock.mockReset();
  fetchMock.mockImplementation(async () => unauthorized());
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  setUnauthorizedHandler(null);
  setLocale('en');
});

describe('session 401 redirect', () => {
  it('redirects to /login preserving the target, with one session-expired toast', async () => {
    const router = await editorOn('/settings');

    const error = await fetchJson('/api/settings').catch((e: unknown) => e);
    await vi.waitFor(() => {
      expect(router.currentRoute.value.path).toBe('/login');
    });

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      redirect: router.currentRoute.value.query.redirect,
      toasts: sessionExpiredToasts(),
      me: useAuthStore().me,
    }).toEqual({ status: 401, redirect: '/settings', toasts: 1, me: null });
  });

  it('adds no second toast and keeps the preserved target on a later 401', async () => {
    const router = await editorOn('/settings');
    await fetchJson('/api/settings').catch(() => undefined);
    await vi.waitFor(() => {
      expect(router.currentRoute.value.path).toBe('/login');
    });

    await fetchJson('/api/permissions').catch(() => undefined);
    await settle();

    expect({
      path: router.currentRoute.value.path,
      redirect: router.currentRoute.value.query.redirect,
      toasts: useToastStore().toasts.length,
    }).toEqual({ path: '/login', redirect: '/settings', toasts: 1 });
  });

  it('handles a burst of parallel 401s with one toast and one landing on /login', async () => {
    const router = await editorOn('/tools');

    await Promise.allSettled([fetchJson('/api/settings'), fetchJson('/api/permissions'), fetchJson('/api/me/sessions')]);
    await vi.waitFor(() => {
      expect(router.currentRoute.value.path).toBe('/login');
    });
    await settle();

    expect({
      path: router.currentRoute.value.path,
      redirect: router.currentRoute.value.query.redirect,
      toasts: useToastStore().toasts.length,
    }).toEqual({ path: '/login', redirect: '/tools', toasts: 1 });
  });

  it('preserves the query of the target route', async () => {
    const router = await editorOn('/chat?draft=1');

    await fetchJson('/api/message', { method: 'POST', body: '{}' }).catch(() => undefined);
    await vi.waitFor(() => {
      expect(router.currentRoute.value.path).toBe('/login');
    });

    expect(router.currentRoute.value.query.redirect).toBe('/chat?draft=1');
  });

  it('drops the redirect when the current path is not a safe redirect target', async () => {
    const router = await editorOn(`/settings?q=${'a'.repeat(2100)}`);

    await fetchJson('/api/settings').catch(() => undefined);
    await vi.waitFor(() => {
      expect(router.currentRoute.value.path).toBe('/login');
    });

    expect(router.currentRoute.value.query.redirect).toBeUndefined();
  });

  it('does not redirect on a 401 from an /api/auth/ endpoint (e.g. a wrong login)', async () => {
    const router = await editorOn('/settings');

    const error = await fetchJson('/api/auth/login', { method: 'POST', body: '{}' }).catch((e: unknown) => e);
    await settle();

    expect({
      status: (error as ApiError).status,
      path: router.currentRoute.value.path,
      toasts: useToastStore().toasts.length,
      authenticated: useAuthStore().isAuthenticated,
    }).toEqual({ status: 401, path: '/settings', toasts: 0, authenticated: true });
  });

  it('does not redirect on a non-401 error', async () => {
    const router = await editorOn('/settings');
    fetchMock.mockImplementation(async () => new Response('{"detail":"Forbidden"}', { status: 403 }));

    await fetchJson('/api/settings').catch(() => undefined);
    await settle();

    expect({ path: router.currentRoute.value.path, authenticated: useAuthStore().isAuthenticated }).toEqual({
      path: '/settings',
      authenticated: true,
    });
  });

  it('forgets the user but stays put on a public page', async () => {
    const router = await editorOn('/reset-password');

    await fetchJson('/api/settings').catch(() => undefined);
    await settle();

    expect({ path: router.currentRoute.value.path, me: useAuthStore().me }).toEqual({
      path: '/reset-password',
      me: null,
    });
  });

  it('stops redirecting once the handler is unregistered', async () => {
    const router = await editorOn('/settings');
    setUnauthorizedHandler(null);

    await fetchJson('/api/settings').catch(() => undefined);
    await settle();

    expect({ path: router.currentRoute.value.path, toasts: useToastStore().toasts.length }).toEqual({
      path: '/settings',
      toasts: 0,
    });
  });
});
