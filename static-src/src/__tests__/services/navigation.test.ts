/**
 * Navigation service tests (issue #15: the Activity page is removed; issue
 * #144: the labels are translated; issue #155: the shell is role-aware).
 *
 * `@/services/navigation` holds `NAV_ITEMS`, the single list of top-level
 * pages that both the desktop nav rail and the mobile bottom tab bar render,
 * so the two never drift apart. Issue #155 supersedes #15's fixed four-page
 * list: `NAV_ITEMS` is now the full ordered list of every top-level area
 * (Chat, Tools, Permissions, Organization, Settings, Platform), each entry
 * tagged with its access `area`, and `navItemsFor(role)` filters it by the
 * role matrix while keeping the order:
 *
 * - Editor: Chat, Tools, Settings.
 * - Org Admin: Chat, Tools, Permissions, Organization, Settings (Permissions
 *   stays a separate top-level page until #161 moves it into Organization).
 * - Viewer: Chat, Settings (no Tools).
 * - Super Admin: Platform only (no chat UI).
 * - Logged out: nothing.
 *
 * There is still no Activity entry. Every entry carries a catalog `labelKey`
 * (#144) and must resolve to a real named route whose `meta.area` matches
 * the entry's area, so the nav, the router and the route guards stay in
 * sync. These tests assert on the exported data, the resolved strings and
 * the router's route table only, never on how a component shows them.
 */
import { describe, it, expect, afterEach } from 'vitest';
import router from '@/router';
import { setLocale, t } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { NAV_ITEMS, navItemsFor } from '@/services/navigation';
import type { ShellRole } from '@/services/access';

/** Path of the router's catch-all record (unknown URLs redirect to `/chat`). */
const CATCH_ALL_PATH = '/:pathMatch(.*)*';

afterEach(() => {
  setLocale('en');
});

describe('navigation NAV_ITEMS', () => {
  it('lists every top-level page in order: chat, tools, permissions, organization, settings, platform', () => {
    expect(NAV_ITEMS.map((item) => item.to)).toEqual([
      '/chat',
      '/tools',
      '/permissions',
      '/organization',
      '/settings',
      '/platform',
    ]);
  });

  it('tags every page with its label key and access area', () => {
    expect(NAV_ITEMS.map(({ to, labelKey, area }) => ({ to, labelKey, area }))).toEqual([
      { to: '/chat', labelKey: 'nav.chat', area: 'chat' },
      { to: '/tools', labelKey: 'nav.tools', area: 'tools' },
      { to: '/permissions', labelKey: 'nav.permissions', area: 'permissions' },
      { to: '/organization', labelKey: 'nav.organization', area: 'organization' },
      { to: '/settings', labelKey: 'nav.settings', area: 'settings' },
      { to: '/platform', labelKey: 'nav.platform', area: 'platform' },
    ]);
  });

  it('labels the pages in order under en: Chat, Tools, Permissions, Organization, Settings, Platform', () => {
    setLocale('en');

    expect(NAV_ITEMS.map((item) => t(item.labelKey))).toEqual([
      'Chat',
      'Tools',
      'Permissions',
      'Organization',
      'Settings',
      'Platform',
    ]);
  });

  it('has no Activity entry, by path or by English label', () => {
    setLocale('en');

    const activity = NAV_ITEMS.filter(
      (item) => item.to === '/activity' || t(item.labelKey).toLowerCase() === 'activity',
    );

    expect(activity).toEqual([]);
  });

  it('gives every entry an icon component', () => {
    expect(NAV_ITEMS.every((item) => Boolean(item.icon))).toBe(true);
  });

  it('has unique paths', () => {
    const paths = NAV_ITEMS.map((item) => item.to);

    expect(new Set(paths).size).toBe(paths.length);
  });
});

describe('navigation navItemsFor (issue #155)', () => {
  it.each([
    ['editor', ['/chat', '/tools', '/settings']],
    ['org_admin', ['/chat', '/tools', '/permissions', '/organization', '/settings']],
    ['viewer', ['/chat', '/settings']],
    ['super_admin', ['/platform']],
    [null, []],
  ] as Array<[ShellRole | null, string[]]>)('shows %s exactly %j, in NAV_ITEMS order', (role, expected) => {
    expect(navItemsFor(role).map((item) => item.to)).toEqual(expected);
  });

  it.each(['editor', 'org_admin', 'viewer', 'super_admin'] as ShellRole[])(
    'returns the NAV_ITEMS entries themselves for %s',
    (role) => {
      const items = navItemsFor(role);

      expect(items.length > 0 && items.every((item) => NAV_ITEMS.includes(item))).toBe(true);
    },
  );

  it('never offers Tools to a Viewer or the chat to a Super Admin', () => {
    expect({
      viewerTools: navItemsFor('viewer').some((item) => item.area === 'tools'),
      superAdminChat: navItemsFor('super_admin').some((item) => item.area === 'chat'),
    }).toEqual({ viewerTools: false, superAdminChat: false });
  });
});

describe('navigation NAV_ITEMS labels (issue #144)', () => {
  it('gives every entry a labelKey from the en source catalog', () => {
    const unknown = NAV_ITEMS.filter((item) => !Object.hasOwn(en, item.labelKey));

    expect(unknown).toEqual([]);
  });

  it('no longer carries a hardcoded label', () => {
    expect(NAV_ITEMS.filter((item) => 'label' in item)).toEqual([]);
  });

  it.each(['de', 'fr'])('resolves every label under %s to a translation, never the raw key', (target) => {
    setLocale(target);

    const labels = NAV_ITEMS.map((item) => ({ key: item.labelKey, label: t(item.labelKey) }));

    expect(labels.filter(({ key, label }) => label.trim() === '' || label === key)).toEqual([]);
  });
});

describe('navigation NAV_ITEMS and the router', () => {
  it('resolves every entry to a named route, never the catch-all', () => {
    const resolved = NAV_ITEMS.map((item) => {
      const route = router.resolve(item.to);
      return {
        to: item.to,
        named: route.name !== undefined,
        catchAll: route.matched.some((record) => record.path === CATCH_ALL_PATH),
      };
    });

    expect(resolved).toEqual(NAV_ITEMS.map((item) => ({ to: item.to, named: true, catchAll: false })));
  });

  it("guards every entry's route with the entry's area (meta.area)", () => {
    const mismatched = NAV_ITEMS.filter(
      (item) => typeof item.area !== 'string' || router.resolve(item.to).meta.area !== item.area,
    );

    expect(mismatched.map((item) => item.to)).toEqual([]);
  });
});
