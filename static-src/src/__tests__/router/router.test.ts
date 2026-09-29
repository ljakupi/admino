/**
 * Router configuration tests (issue #15: the Activity page is removed; issue
 * #155: auth pages and role-aware route guards).
 *
 * Issue #155 supersedes #15's "exactly four named routes": the router now
 * also has the public auth pages (login, forgot-password, reset-password,
 * accept-invitation) and the Organization and Platform areas. There is still
 * no `activity` route: `/activity` resolves to the catch-all record, which
 * redirects to `/chat` (as `/` does).
 *
 * Route meta drives the guards: the auth pages carry `meta.public === true`;
 * every area route carries `meta.area` equal to its name. `@/router` exports
 * `createAppRouter(history)` (the default export stays the app's router, on
 * the web history). Its `beforeEach` awaits the auth store's `ensureLoaded()`
 * (one `GET /api/auth/me` per app load) and applies `resolveNavigation`:
 *
 * - Logged out: protected pages go to /login with `?redirect=` preserving
 *   the target; the public pages stay reachable.
 * - Per role: an area the role may not open sends it home (Super Admin →
 *   /platform, members → /chat); a logged-in user never sees /login.
 *
 * `@/api/auth` is mocked (only `getMe` answers); no app or component is
 * mounted. Page components are lazy imports the router resolves on
 * navigation, which only loads the modules.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createMemoryHistory, type Router } from 'vue-router';
import { createPinia, setActivePinia } from 'pinia';
import router, { createAppRouter } from '@/router';
import { ApiError } from '@/api/client';
import { setLocale } from '@/i18n';
import type { MeResponse } from '@/api/types';

const { getMeMock } = vi.hoisted(() => ({ getMeMock: vi.fn<() => Promise<MeResponse>>() }));

vi.mock('@/api/auth', () => ({
  getMe: getMeMock,
  login: vi.fn(),
  logout: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  getInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

/** Path of the catch-all record that redirects unknown URLs to `/chat`. */
const CATCH_ALL_PATH = '/:pathMatch(.*)*';

const PUBLIC_ROUTES = ['accept-invitation', 'forgot-password', 'login', 'reset-password'];
const AREA_ROUTES = ['chat', 'organization', 'permissions', 'platform', 'settings', 'tools'];

const ORG_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';

type Role = 'super_admin' | 'org_admin' | 'editor' | 'viewer';

function meAs(role: Role): MeResponse {
  if (role === 'super_admin') {
    return {
      user_id: '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f',
      kind: 'super_admin',
      org_id: null,
      role: null,
      ui_language: 'en',
      response_language: null,
    };
  }
  return {
    user_id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
    kind: 'member',
    org_id: ORG_ID,
    role,
    ui_language: 'en',
    response_language: null,
  };
}

function namedRoutes(): string[] {
  return router
    .getRoutes()
    .flatMap((record) => (record.name === undefined ? [] : [String(record.name)]))
    .sort();
}

function metaOf(name: string): Record<string, unknown> {
  const record = router.getRoutes().find((r) => r.name === name);
  if (!record) throw new Error(`no route named ${name}`);
  return record.meta as Record<string, unknown>;
}

/** A fresh router on a memory history (no navigation has happened yet). */
function freshRouter(): Router {
  return createAppRouter(createMemoryHistory());
}

/** Navigates a fresh router to `target` and returns where it ended up. */
async function landing(target: string): Promise<{ path: string; redirect: unknown }> {
  const r = freshRouter();
  await r.push(target);
  const route = r.currentRoute.value;
  return { path: route.path, redirect: route.query.redirect };
}

function loggedOut(): void {
  getMeMock.mockRejectedValue(new ApiError(401, 'Unauthorized', 'Unauthorized'));
}

function loggedInAs(role: Role): void {
  getMeMock.mockResolvedValue(meAs(role));
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
  getMeMock.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- Route table ----------------------------------------------------------

describe('router routes', () => {
  it('has no activity route', () => {
    expect(router.hasRoute('activity')).toBe(false);
  });

  it('has exactly the auth pages and the six area routes as named routes', () => {
    expect(namedRoutes()).toEqual([
      'accept-invitation',
      'chat',
      'forgot-password',
      'login',
      'organization',
      'permissions',
      'platform',
      'reset-password',
      'settings',
      'tools',
    ]);
  });

  it.each(PUBLIC_ROUTES)('marks the %s page public, with no area', (name) => {
    const meta = metaOf(name);

    expect({ public: meta.public, area: meta.area }).toEqual({ public: true, area: undefined });
  });

  it.each(AREA_ROUTES)('guards the %s route with meta.area %s, never public', (name) => {
    const meta = metaOf(name);

    expect({ area: meta.area, public: Boolean(meta.public) }).toEqual({ area: name, public: false });
  });

  it.each([
    ['/login', 'login'],
    ['/forgot-password', 'forgot-password'],
    ['/reset-password', 'reset-password'],
    ['/accept-invitation', 'accept-invitation'],
    ['/organization', 'organization'],
    ['/platform', 'platform'],
  ])('resolves %s to the %s route', (path, name) => {
    expect(router.resolve(path).name).toBe(name);
  });

  it('exports a factory that builds an independent router with the same route table', () => {
    const other = freshRouter();

    expect({
      independent: other !== router,
      names: other
        .getRoutes()
        .flatMap((record) => (record.name === undefined ? [] : [String(record.name)]))
        .sort(),
    }).toEqual({ independent: true, names: namedRoutes() });
  });
});

describe('router /activity', () => {
  it('resolves /activity to the catch-all record only', () => {
    const resolved = router.resolve('/activity');

    expect(resolved.matched.map((record) => record.path)).toEqual([CATCH_ALL_PATH]);
  });

  it('redirects a logged-in editor from /activity to /chat', async () => {
    loggedInAs('editor');

    expect((await landing('/activity')).path).toBe('/chat');
  });
});

// --- Guards: logged out ---------------------------------------------------

describe('router guards while logged out', () => {
  beforeEach(loggedOut);

  it('sends /settings to /login, preserving the target as ?redirect=', async () => {
    expect(await landing('/settings')).toEqual({ path: '/login', redirect: '/settings' });
  });

  it('sends / to /login with ?redirect=/chat (/ redirects to /chat first)', async () => {
    expect(await landing('/')).toEqual({ path: '/login', redirect: '/chat' });
  });

  it('sends an unknown URL to /login with ?redirect=/chat (the catch-all redirects first)', async () => {
    expect(await landing('/activity')).toEqual({ path: '/login', redirect: '/chat' });
  });

  it('sends /platform to /login, preserving the target', async () => {
    expect(await landing('/platform')).toEqual({ path: '/login', redirect: '/platform' });
  });

  it.each(['/login', '/forgot-password', '/reset-password', '/accept-invitation'])(
    'lets a logged-out user open %s',
    async (path) => {
      expect((await landing(path)).path).toBe(path);
    },
  );

  it('fails closed when /api/auth/me errors with something other than 401', async () => {
    getMeMock.mockReset();
    getMeMock.mockRejectedValue(new ApiError(500, 'Internal Server Error'));

    expect(await landing('/chat')).toEqual({ path: '/login', redirect: '/chat' });
  });

  it('fails closed when /api/auth/me is unreachable', async () => {
    getMeMock.mockReset();
    getMeMock.mockRejectedValue(new TypeError('Failed to fetch'));

    expect((await landing('/tools')).path).toBe('/login');
  });
});

// --- Guards: per role -----------------------------------------------------

describe('router guards per role', () => {
  it.each([
    ['editor', '/tools', '/tools'],
    ['editor', '/chat', '/chat'],
    ['editor', '/settings', '/settings'],
    ['editor', '/organization', '/chat'],
    ['editor', '/permissions', '/chat'],
    ['editor', '/platform', '/chat'],
    ['viewer', '/tools', '/chat'],
    ['viewer', '/chat', '/chat'],
    ['viewer', '/settings', '/settings'],
    ['viewer', '/organization', '/chat'],
    ['org_admin', '/organization', '/organization'],
    ['org_admin', '/permissions', '/permissions'],
    ['org_admin', '/tools', '/tools'],
    ['org_admin', '/platform', '/chat'],
    ['super_admin', '/chat', '/platform'],
    ['super_admin', '/', '/platform'],
    ['super_admin', '/settings', '/platform'],
    ['super_admin', '/tools', '/platform'],
    ['super_admin', '/platform', '/platform'],
  ] as Array<[Role, string, string]>)('%s pushing %s ends on %s', async (role, target, expected) => {
    loggedInAs(role);

    expect((await landing(target)).path).toBe(expected);
  });

  it('sends a logged-in editor away from /login to /chat', async () => {
    loggedInAs('editor');

    expect((await landing('/login')).path).toBe('/chat');
  });

  it('sends a logged-in Super Admin away from /login to /platform', async () => {
    loggedInAs('super_admin');

    expect((await landing('/login')).path).toBe('/platform');
  });

  it('follows a safe ?redirect= when a logged-in editor opens /login', async () => {
    loggedInAs('editor');

    expect((await landing('/login?redirect=/settings')).path).toBe('/settings');
  });

  it('still applies the role guard to the ?redirect= target (viewer -> /tools ends on /chat)', async () => {
    loggedInAs('viewer');

    expect((await landing('/login?redirect=/tools')).path).toBe('/chat');
  });

  it('ignores an off-site ?redirect= on /login', async () => {
    loggedInAs('editor');

    expect((await landing('/login?redirect=//evil.example')).path).toBe('/chat');
  });

  it.each(['/reset-password', '/accept-invitation', '/forgot-password'])(
    'lets a logged-in editor open the public page %s',
    async (path) => {
      loggedInAs('editor');

      expect((await landing(path)).path).toBe(path);
    },
  );
});

// --- ensureLoaded caching -------------------------------------------------

describe('router session loading', () => {
  it('fetches /api/auth/me only once across several navigations', async () => {
    loggedInAs('editor');
    const r = freshRouter();

    await r.push('/chat');
    await r.push('/tools');
    await r.push('/settings');

    expect({ path: r.currentRoute.value.path, calls: getMeMock.mock.calls.length }).toEqual({
      path: '/settings',
      calls: 1,
    });
  });

  it('does not refetch /api/auth/me on every navigation while logged out', async () => {
    loggedOut();
    const r = freshRouter();

    await r.push('/settings');
    await r.push('/chat');
    await r.push('/reset-password');

    expect({ path: r.currentRoute.value.path, calls: getMeMock.mock.calls.length }).toEqual({
      path: '/reset-password',
      calls: 1,
    });
  });
});
