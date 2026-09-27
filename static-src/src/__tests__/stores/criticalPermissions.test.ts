/**
 * Critical-permissions store tests (issue #149).
 *
 * The re-auth token prompt is gone: `promote(tool, action)` takes no token and
 * calls the API with just the tool and action. Until #161 the backend refuses
 * promotions with 403; the store records that error (an error toast carrying
 * the backend's message), rethrows it, and leaves the permission in `deny`
 * with no cooldown. The network layer (`@/api/critical-permissions`) is
 * mocked; errors use the real `ApiError` class.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { ApiError } from '@/api/client';
import {
  getCriticalPermissions,
  promoteCriticalPermission,
} from '@/api/critical-permissions';
import { useCriticalPermissionsStore } from '@/stores/criticalPermissions';
import { useToastStore } from '@/stores/toasts';
import type { CriticalPermissionsResponse } from '@/api/types';

vi.mock('@/api/critical-permissions', () => ({
  getCriticalPermissions: vi.fn(),
  promoteCriticalPermission: vi.fn(),
  demoteCriticalPermission: vi.fn(),
  cancelPendingPromotion: vi.fn(),
}));

const mockedGet = vi.mocked(getCriticalPermissions);
const mockedPromote = vi.mocked(promoteCriticalPermission);

const UNAVAILABLE = 'Critical permission promotions are temporarily unavailable.';

function allDenied(): CriticalPermissionsResponse {
  return {
    permissions: [
      { tool: 'gmail', action: 'send', state: 'deny', pending_at: null },
      { tool: 'outlook', action: 'send', state: 'deny', pending_at: null },
      { tool: 'google_calendar', action: 'update', state: 'deny', pending_at: null },
      { tool: 'outlook_calendar', action: 'update', state: 'deny', pending_at: null },
    ],
  };
}

/** A store loaded from the backend (every permission denied, no cooldown). */
async function loadedStore() {
  mockedGet.mockResolvedValueOnce(allDenied());
  const store = useCriticalPermissionsStore();
  await store.load();
  if (store.error) throw new Error(`test setup: load failed: ${store.error}`);
  return store;
}

beforeEach(() => {
  setActivePinia(createPinia());
  mockedGet.mockReset();
  mockedPromote.mockReset();
});

describe('criticalPermissionsStore promote', () => {
  it('calls the API with only the tool and action (no token)', async () => {
    mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', UNAVAILABLE));
    const store = await loadedStore();

    await store.promote('gmail', 'send').catch(() => undefined);

    expect(mockedPromote.mock.calls).toStrictEqual([['gmail', 'send']]);
  });

  it('on a 403 rethrows the ApiError, shows the backend message in an error toast and keeps deny', async () => {
    const refusal = new ApiError(403, 'Forbidden', UNAVAILABLE);
    mockedPromote.mockRejectedValueOnce(refusal);
    const store = await loadedStore();

    const thrown = await store.promote('gmail', 'send').catch((e: unknown) => e);

    const toasts = useToastStore().toasts;
    expect(thrown).toBe(refusal);
    expect(
      toasts.some(
        (toast) => toast.kind === 'error' && `${toast.title} ${toast.body ?? ''}`.includes(UNAVAILABLE),
      ),
    ).toBe(true);
    expect(toasts.some((toast) => toast.kind === 'success')).toBe(false);
    expect(store.getState('gmail', 'send')).toEqual({ state: 'deny', pendingAt: null });
  });
});
