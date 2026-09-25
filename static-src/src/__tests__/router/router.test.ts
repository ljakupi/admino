/**
 * Router configuration tests (issue #15: the Activity page is removed).
 *
 * After #15 the router has exactly four named page routes (chat, tools,
 * permissions, settings) and no `activity` route. `/activity` is no longer a
 * real page: it resolves to the catch-all record, which redirects to `/chat`.
 * These tests check the router's route table and navigation outcome only.
 * No app or component is mounted.
 */
import { describe, it, expect } from 'vitest';
import router from '@/router';

/** Path of the catch-all record that redirects unknown URLs to `/chat`. */
const CATCH_ALL_PATH = '/:pathMatch(.*)*';

function namedRoutes(): string[] {
  return router
    .getRoutes()
    .flatMap((record) => (record.name === undefined ? [] : [String(record.name)]))
    .sort();
}

describe('router routes', () => {
  it('has no activity route', () => {
    expect(router.hasRoute('activity')).toBe(false);
  });

  it('has exactly the chat, tools, permissions and settings named routes', () => {
    expect(namedRoutes()).toEqual(['chat', 'permissions', 'settings', 'tools']);
  });
});

describe('router /activity', () => {
  it('resolves /activity to the catch-all record only', () => {
    const resolved = router.resolve('/activity');

    expect(resolved.matched.map((record) => record.path)).toEqual([CATCH_ALL_PATH]);
  });

  it('redirects a navigation to /activity to /chat', async () => {
    await router.push('/activity');

    expect(router.currentRoute.value.path).toBe('/chat');
  });
});
