/**
 * Route guard logic tests (issue #155: route guards mirror the backend; the
 * backend stays authoritative).
 *
 * `@/router/guards` is pure: the router's `beforeEach` feeds it the target
 * route and the current shell role.
 *
 * - `PUBLIC_PATHS`: the auth pages anyone may open (login, forgot password,
 *   reset password, accept invitation).
 * - `safeRedirect(value)`: the `?redirect=` target is used only when it is an
 *   in-app path: a string starting with one '/', not '//' or '/\' (both are
 *   protocol-relative URLs to another host), with no backslash, no control
 *   character, at most 2048 characters, and not pointing back at a public
 *   auth page. Anything else is `null` (no open redirect, no login loop).
 * - `resolveNavigation(to, role)`:
 *   a) Public pages: a logged-in user never sees the login page (sent to the
 *      safe redirect or home); the other public pages are open to everyone.
 *   b) A protected page while logged out: to /login, preserving the target
 *      as `?redirect=` when it is safe.
 *   c) A protected page the role may not open: to the role's home. Issue
 *      #161: an Org Admin opening /permissions goes home (the matrix lives
 *      under Organization); an Editor or Viewer may open the read-only
 *      /permissions summary but not /organization.
 *   d) Otherwise the navigation proceeds (`true`).
 */
import { describe, it, expect } from 'vitest';
import { PUBLIC_PATHS, resolveNavigation, safeRedirect } from '@/router/guards';
import type { Area, ShellRole } from '@/services/access';

type Target = Parameters<typeof resolveNavigation>[0];

const ROLES: readonly ShellRole[] = ['super_admin', 'org_admin', 'editor', 'viewer'];
const AREAS: readonly Area[] = ['chat', 'tools', 'permissions', 'organization', 'settings', 'platform'];
const OTHER_PUBLIC_PAGES = ['/forgot-password', '/reset-password', '/accept-invitation'] as const;

const HOME: Record<ShellRole, string> = {
  super_admin: '/platform',
  org_admin: '/chat',
  editor: '/chat',
  viewer: '/chat',
};

const ALLOWED: Record<ShellRole, readonly Area[]> = {
  super_admin: ['platform'],
  org_admin: ['chat', 'tools', 'organization', 'settings'],
  editor: ['chat', 'tools', 'permissions', 'settings'],
  viewer: ['chat', 'permissions', 'settings'],
};

const DEL = String.fromCharCode(0x7f);
const NUL = String.fromCharCode(0);
const UNIT_SEPARATOR = String.fromCharCode(0x1f);

/** A public route target, as the router's `to` would describe it. */
function publicTarget(path: string, query: Record<string, unknown> = {}, fullPath?: string): Target {
  return { path, fullPath: fullPath ?? path, query, meta: { public: true } };
}

/** A protected route target for `area`. */
function areaTarget(area: Area, fullPath = `/${area}`, query: Record<string, unknown> = {}): Target {
  return { path: `/${area}`, fullPath, query, meta: { area } };
}

// --- PUBLIC_PATHS ---------------------------------------------------------

describe('guards PUBLIC_PATHS', () => {
  it('lists exactly the four auth pages', () => {
    expect([...PUBLIC_PATHS]).toEqual(['/login', '/forgot-password', '/reset-password', '/accept-invitation']);
  });
});

// --- safeRedirect ---------------------------------------------------------

describe('guards safeRedirect', () => {
  it.each([
    '/settings',
    '/chat',
    '/chat?x=1',
    '/tools#a',
    '/settings/nested/path',
    '/organization?tab=users&filter=%2F',
    '/loginx',
    `/${'a'.repeat(2047)}`,
  ])('keeps the in-app path %j', (value) => {
    expect(safeRedirect(value)).toBe(value);
  });

  const refused: Array<[string, unknown]> = [
    ['an absolute URL', 'https://evil.example'],
    ['an absolute URL with an in-app path', 'http://evil.example/chat'],
    ['a protocol-relative URL', '//evil.example'],
    ['a protocol-relative URL with a path', '//evil.example/chat'],
    ['a slash-backslash URL', '/\\evil.example'],
    ['a double backslash', '\\\\evil.example'],
    ['a backslash inside the path', '/chat\\..\\x'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a relative path', 'chat'],
    ['a leading space', ' /chat'],
    ['an empty string', ''],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['a list (repeated query key)', ['/chat']],
    ['an object', { path: '/chat' }],
    ['the login page', '/login'],
    ['the login page with a redirect', '/login?redirect=/x'],
    ['the login page with a fragment', '/login#x'],
    ['the forgot password page', '/forgot-password'],
    ['the reset password page', '/reset-password'],
    ['the reset password page with its token', '/reset-password#token=abc'],
    ['the accept invitation page', '/accept-invitation'],
    ['the accept invitation page with a query', '/accept-invitation?x=1'],
    ['a trailing newline', '/chat\n'],
    ['a carriage return', '/chat\r\n/x'],
    ['a tab', '/\t/evil.example'],
    ['a NUL', `/ch${NUL}at`],
    ['a unit separator (U+001F)', `/chat${UNIT_SEPARATOR}`],
    ['a DEL (U+007F)', `/chat${DEL}`],
    ['2049 characters', `/${'a'.repeat(2048)}`],
    // Security audit: percent-encoded forms of the refused shapes are refused too.
    ['a percent-encoded protocol-relative URL', '/%2F%2Fevil.example'],
    ['a percent-encoded second slash', '/%2Fevil.example'],
    ['a lower-case percent-encoded slash', '/%2fevil.example'],
    ['a percent-encoded backslash', '/%5Cevil.example'],
    ['a percent-encoded backslash inside the path', '/chat%5C..%5Cx'],
    ['a percent-encoded newline', '/chat%0A'],
    ['a percent-encoded public page', '/%6Cogin'],
    ['a malformed percent escape', '/chat%E0%A4%A'],
  ];

  it.each(refused)('refuses %s', (_label, value) => {
    expect(safeRedirect(value)).toBeNull();
  });
});

// --- resolveNavigation: public pages -------------------------------------

describe('guards resolveNavigation public pages', () => {
  it('lets a logged-out user open the login page', () => {
    expect(resolveNavigation(publicTarget('/login'), null)).toBe(true);
  });

  it.each(ROLES)('sends a logged-in %s away from the login page to its home', (role) => {
    expect(resolveNavigation(publicTarget('/login'), role)).toEqual({ path: HOME[role] });
  });

  it('sends a logged-in user from the login page to a safe ?redirect= target', () => {
    const to = publicTarget('/login', { redirect: '/settings' }, '/login?redirect=%2Fsettings');

    expect(resolveNavigation(to, 'editor')).toEqual({ path: '/settings' });
  });

  it.each([
    ['an absolute URL', 'https://evil.example'],
    ['a protocol-relative URL', '//evil.example'],
    ['a list', ['/settings']],
    ['the login page itself', '/login'],
    ['another public page', '/reset-password'],
    ['a number', 7],
  ] as Array<[string, unknown]>)('ignores an unsafe ?redirect= (%s) and sends the user home', (_label, redirect) => {
    expect(resolveNavigation(publicTarget('/login', { redirect }), 'super_admin')).toEqual({ path: '/platform' });
  });

  const everyone: Array<ShellRole | null> = [null, ...ROLES];
  const openPages = OTHER_PUBLIC_PAGES.flatMap((path) =>
    everyone.map((role): [string, ShellRole | null] => [path, role]),
  );

  it.each(openPages)('opens %s for %s', (path, role) => {
    expect(resolveNavigation(publicTarget(path), role)).toBe(true);
  });
});

// --- resolveNavigation: logged out ---------------------------------------

describe('guards resolveNavigation while logged out', () => {
  it.each(AREAS)('sends /%s to /login, preserving it as ?redirect=', (area) => {
    expect(resolveNavigation(areaTarget(area), null)).toEqual({
      path: '/login',
      query: { redirect: `/${area}` },
    });
  });

  it('preserves the full path, query included, as ?redirect=', () => {
    const to = areaTarget('settings', '/settings?section=llm', { section: 'llm' });

    expect(resolveNavigation(to, null)).toEqual({ path: '/login', query: { redirect: '/settings?section=llm' } });
  });

  it.each([
    ['longer than 2048 characters', `/settings?q=${'a'.repeat(2100)}`],
    ['with a control character', '/settings\n'],
    ['protocol-relative', '//evil.example/settings'],
  ])('sends the user to /login without a redirect when the target is %s', (_label, fullPath) => {
    expect(resolveNavigation(areaTarget('settings', fullPath), null)).toEqual({ path: '/login' });
  });
});

// --- resolveNavigation: per role, per area --------------------------------

describe('guards resolveNavigation per role', () => {
  const matrix = ROLES.flatMap((role) =>
    AREAS.map((area): [ShellRole, Area, boolean] => [role, area, ALLOWED[role].includes(area)]),
  );

  it.each(matrix)('%s -> /%s is allowed: %s (else sent home)', (role, area, allowed) => {
    const expected = allowed ? true : { path: HOME[role] };

    expect(resolveNavigation(areaTarget(area), role)).toEqual(expected);
  });

  it.each([
    ['viewer', 'tools', '/chat'],
    ['editor', 'organization', '/chat'],
    ['viewer', 'organization', '/chat'],
    ['org_admin', 'permissions', '/chat'],
    ['org_admin', 'platform', '/chat'],
    ['super_admin', 'chat', '/platform'],
    ['super_admin', 'settings', '/platform'],
    ['super_admin', 'tools', '/platform'],
  ] as Array<[ShellRole, Area, string]>)('sends %s from /%s to %s', (role, area, home) => {
    expect(resolveNavigation(areaTarget(area), role)).toEqual({ path: home });
  });

  it.each([
    ['editor', 'permissions'],
    ['viewer', 'permissions'],
    ['org_admin', 'organization'],
  ] as Array<[ShellRole, Area]>)('lets %s open /%s (issue #161)', (role, area) => {
    expect(resolveNavigation(areaTarget(area), role)).toBe(true);
  });
});
