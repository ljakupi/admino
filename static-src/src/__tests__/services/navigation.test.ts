/**
 * Navigation service tests (issue #15: the Activity page is removed).
 *
 * `@/services/navigation` holds `NAV_ITEMS`, the single list of top-level
 * pages that both the desktop nav rail and the mobile bottom tab bar render
 * (they used to duplicate it inline). After #15 the list has exactly four
 * pages, in order: Chat, Tools, Permissions, Settings. There is no Activity
 * entry. Every entry must also resolve to a real named route, so the nav and
 * the router stay in sync. These tests assert on the exported data and the
 * router's route table only, never on how a component shows them.
 */
import { describe, it, expect } from 'vitest';
import router from '@/router';
import { NAV_ITEMS } from '@/services/navigation';

/** Path of the router's catch-all record (unknown URLs redirect to `/chat`). */
const CATCH_ALL_PATH = '/:pathMatch(.*)*';

describe('navigation NAV_ITEMS', () => {
  it('lists the four page paths in order: chat, tools, permissions, settings', () => {
    expect(NAV_ITEMS.map((item) => item.to)).toEqual([
      '/chat',
      '/tools',
      '/permissions',
      '/settings',
    ]);
  });

  it('labels the four pages in order: Chat, Tools, Permissions, Settings', () => {
    expect(NAV_ITEMS.map((item) => item.label)).toEqual([
      'Chat',
      'Tools',
      'Permissions',
      'Settings',
    ]);
  });

  it('has no Activity entry, by path or by label', () => {
    const activity = NAV_ITEMS.filter(
      (item) => item.to === '/activity' || item.label.toLowerCase() === 'activity',
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
});
