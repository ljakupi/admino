/**
 * Navigation service tests (issue #15: the Activity page is removed; issue
 * #144: the labels are translated).
 *
 * `@/services/navigation` holds `NAV_ITEMS`, the single list of top-level
 * pages that both the desktop nav rail and the mobile bottom tab bar render
 * (they used to duplicate it inline). After #15 the list has exactly four
 * pages, in order: Chat, Tools, Permissions, Settings. There is no Activity
 * entry. Every entry must also resolve to a real named route, so the nav and
 * the router stay in sync.
 *
 * After #144 an entry carries a catalog `labelKey` instead of a hardcoded
 * English `label`; components render `t(item.labelKey)`, so the labels follow
 * the active locale reactively. The label assertions therefore resolve the
 * keys through the i18n singleton. These tests assert on the exported data,
 * the resolved strings and the router's route table only, never on how a
 * component shows them.
 */
import { describe, it, expect, afterEach } from 'vitest';
import router from '@/router';
import { setLocale, t } from '@/i18n';
import { en } from '@/i18n/locales/en';
import { NAV_ITEMS } from '@/services/navigation';

/** Path of the router's catch-all record (unknown URLs redirect to `/chat`). */
const CATCH_ALL_PATH = '/:pathMatch(.*)*';

afterEach(() => {
  setLocale('en');
});

describe('navigation NAV_ITEMS', () => {
  it('lists the four page paths in order: chat, tools, permissions, settings', () => {
    expect(NAV_ITEMS.map((item) => item.to)).toEqual([
      '/chat',
      '/tools',
      '/permissions',
      '/settings',
    ]);
  });

  it('labels the four pages in order under en: Chat, Tools, Permissions, Settings', () => {
    setLocale('en');

    expect(NAV_ITEMS.map((item) => t(item.labelKey))).toEqual([
      'Chat',
      'Tools',
      'Permissions',
      'Settings',
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
});
