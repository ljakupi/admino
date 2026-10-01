/**
 * Critical-permissions store tests (issue #149; issue #161: per-org critical
 * permissions, promotion needs password re-auth).
 *
 * Contract (issue #161):
 * - New state: `reauthTarget` ({ tool, action } | null, null at first),
 *   `reauthError` (string | null) and `reauthBusy` (boolean).
 * - `toggle(tool, action, now = Date.now())`:
 *   - an "on" row (state 'confirm', not pending) -> demote request;
 *   - a pending row (pendingAt set and `now - pendingAt < COOLDOWN_SEC * 1000`)
 *     -> cancel request;
 *   - otherwise -> opens the re-auth prompt (`reauthTarget = { tool, action }`,
 *     `reauthError = null`) and makes NO request.
 * - `confirmReauth(password)`: no target -> nothing happens. Otherwise it
 *   promotes the target with the password. Success -> the row takes the
 *   returned state/pendingAt, a success toast, `reauthTarget = null`. A 403
 *   (wrong password / locked) -> `reauthError = t('reauth.error.wrongPassword')`,
 *   the prompt stays open, nothing is thrown. Any other error ->
 *   `reauthError = t('reauth.error.failed')`, the prompt stays open.
 *   `reauthBusy` is true only while the request is in flight.
 * - `cancelReauth()`: closes the prompt (target and error cleared), no request.
 * - `promote(tool, action, password)` passes the password to the API client.
 * - The password is never kept in any store state.
 *
 * The network layer (`@/api/critical-permissions`) is mocked; errors use the
 * real `ApiError` class.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { ApiError } from '@/api/client';
import {
  cancelPendingPromotion,
  demoteCriticalPermission,
  getCriticalPermissions,
  promoteCriticalPermission,
} from '@/api/critical-permissions';
import { t, type MessageKey } from '@/i18n';
import { COOLDOWN_SEC, useCriticalPermissionsStore } from '@/stores/criticalPermissions';
import { useToastStore } from '@/stores/toasts';
import type {
  CriticalPermissionEntry,
  CriticalPermissionPatchResponse,
  CriticalPermissionsResponse,
} from '@/api/types';

vi.mock('@/api/critical-permissions', () => ({
  getCriticalPermissions: vi.fn(),
  promoteCriticalPermission: vi.fn(),
  demoteCriticalPermission: vi.fn(),
  cancelPendingPromotion: vi.fn(),
}));

const mockedGet = vi.mocked(getCriticalPermissions);
const mockedPromote = vi.mocked(promoteCriticalPermission);
const mockedDemote = vi.mocked(demoteCriticalPermission);
const mockedCancel = vi.mocked(cancelPendingPromotion);

const PASSWORD = 'Zebra-Quartz-Lantern-91';
const REAUTH_FAILED = 'Re-authentication failed.';
const NOW = Date.parse('2026-10-01T10:00:00.000Z');
const COOLDOWN_MS = COOLDOWN_SEC * 1000;

const wrongPasswordText = (): string => t('reauth.error.wrongPassword' as MessageKey);
const failedText = (): string => t('reauth.error.failed' as MessageKey);

type Overrides = Record<string, Partial<Pick<CriticalPermissionEntry, 'state' | 'pending_at'>>>;

function list(overrides: Overrides = {}): CriticalPermissionsResponse {
  const pairs: Array<[string, string]> = [
    ['gmail', 'send'],
    ['outlook', 'send'],
    ['google_calendar', 'update'],
    ['outlook_calendar', 'update'],
  ];
  return {
    permissions: pairs.map(([tool, action]) => ({
      tool,
      action,
      state: 'deny',
      pending_at: null,
      ...(overrides[`${tool}.${action}`] ?? {}),
    })),
  };
}

function stateOf(
  tool: string,
  action: string,
  state: 'deny' | 'confirm' = 'deny',
  pendingAt: number | null = null,
): CriticalPermissionPatchResponse {
  return { tool, action, state, pending_at: pendingAt === null ? null : new Date(pendingAt).toISOString() };
}

/** A store loaded from the backend (`overrides` per `tool.action`). */
async function loadedStore(overrides: Overrides = {}) {
  mockedGet.mockResolvedValueOnce(list(overrides));
  const store = useCriticalPermissionsStore();
  await store.load();
  if (store.error) throw new Error(`test setup: load failed: ${store.error}`);
  return store;
}

/** A promise the test settles by hand. Pre-implementation nobody may consume it. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

/** 'resolved', or whatever the promise rejected with. */
async function outcomeOf(promise: unknown): Promise<unknown> {
  try {
    await promise;
    return 'resolved';
  } catch (e) {
    return e;
  }
}

/** Every request the store made to the write endpoints, by kind. */
function writeCalls() {
  return {
    promote: mockedPromote.mock.calls.length,
    demote: mockedDemote.mock.calls.length,
    cancel: mockedCancel.mock.calls.length,
  };
}

/** True when `needle` occurs in any string reachable from `value` (objects, arrays, Maps, Sets). */
function containsString(value: unknown, needle: string, seen = new Set<unknown>()): boolean {
  if (typeof value === 'string') return value.includes(needle);
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (value instanceof Map) {
    return [...value.entries()].some(([k, v]) => containsString(k, needle, seen) || containsString(v, needle, seen));
  }
  if (value instanceof Set) return [...value].some((v) => containsString(v, needle, seen));
  return Object.values(value as Record<string, unknown>).some((v) => containsString(v, needle, seen));
}

beforeEach(() => {
  setActivePinia(createPinia());
  mockedGet.mockReset();
  mockedPromote.mockReset();
  mockedDemote.mockReset();
  mockedCancel.mockReset();
  mockedDemote.mockImplementation(async (tool, action) => stateOf(tool, action));
  mockedCancel.mockImplementation(async (tool, action) => stateOf(tool, action));
});

// --- initial state --------------------------------------------------------

describe('criticalPermissionsStore re-auth state', () => {
  it('starts with no re-auth target, no error and not busy', () => {
    const store = useCriticalPermissionsStore();

    expect({
      reauthTarget: store.reauthTarget,
      reauthError: store.reauthError,
      reauthBusy: store.reauthBusy,
    }).toStrictEqual({ reauthTarget: null, reauthError: null, reauthBusy: false });
  });
});

// --- toggle ---------------------------------------------------------------

describe('criticalPermissionsStore toggle', () => {
  it('demotes an "on" row (confirm, not pending) without opening the re-auth prompt', async () => {
    const store = await loadedStore({ 'gmail.send': { state: 'confirm' } });

    await store.toggle('gmail', 'send', NOW);

    expect({
      demote: mockedDemote.mock.calls,
      promote: mockedPromote.mock.calls.length,
      cancel: mockedCancel.mock.calls.length,
      reauthTarget: store.reauthTarget,
    }).toStrictEqual({ demote: [['gmail', 'send']], promote: 0, cancel: 0, reauthTarget: null });
  });

  it('cancels a pending promotion inside the cooldown without opening the re-auth prompt', async () => {
    const pendingAt = new Date(NOW - 60_000).toISOString();
    const store = await loadedStore({ 'outlook.send': { pending_at: pendingAt } });

    await store.toggle('outlook', 'send', NOW);

    expect({
      cancel: mockedCancel.mock.calls,
      promote: mockedPromote.mock.calls.length,
      demote: mockedDemote.mock.calls.length,
      reauthTarget: store.reauthTarget,
    }).toStrictEqual({ cancel: [['outlook', 'send']], promote: 0, demote: 0, reauthTarget: null });
  });

  it('still cancels one millisecond before the cooldown ends', async () => {
    const pendingAt = new Date(NOW - (COOLDOWN_MS - 1)).toISOString();
    const store = await loadedStore({ 'outlook.send': { pending_at: pendingAt } });

    await store.toggle('outlook', 'send', NOW);

    expect({ cancel: mockedCancel.mock.calls, reauthTarget: store.reauthTarget }).toStrictEqual({
      cancel: [['outlook', 'send']],
      reauthTarget: null,
    });
  });

  it('uses Date.now() when no time is given (a fresh pending row is cancelled)', async () => {
    const pendingAt = new Date(Date.now() - 30_000).toISOString();
    const store = await loadedStore({ 'gmail.send': { pending_at: pendingAt } });

    await store.toggle('gmail', 'send');

    expect({ cancel: mockedCancel.mock.calls, reauthTarget: store.reauthTarget }).toStrictEqual({
      cancel: [['gmail', 'send']],
      reauthTarget: null,
    });
  });

  it('opens the re-auth prompt for an "off" row and makes no request', async () => {
    const store = await loadedStore();

    await store.toggle('gmail', 'send', NOW);

    expect({
      reauthTarget: store.reauthTarget,
      reauthError: store.reauthError,
      writes: writeCalls(),
      loads: mockedGet.mock.calls.length,
    }).toStrictEqual({
      reauthTarget: { tool: 'gmail', action: 'send' },
      reauthError: null,
      writes: { promote: 0, demote: 0, cancel: 0 },
      loads: 1,
    });
  });

  it('opens the re-auth prompt once the cooldown has passed (exactly COOLDOWN_SEC)', async () => {
    const pendingAt = new Date(NOW - COOLDOWN_MS).toISOString();
    const store = await loadedStore({ 'google_calendar.update': { pending_at: pendingAt } });

    await store.toggle('google_calendar', 'update', NOW);

    expect({ reauthTarget: store.reauthTarget, writes: writeCalls() }).toStrictEqual({
      reauthTarget: { tool: 'google_calendar', action: 'update' },
      writes: { promote: 0, demote: 0, cancel: 0 },
    });
  });

  it('clears an earlier re-auth error when it opens the prompt for another row', async () => {
    mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);
    await store.confirmReauth('wrong');
    if (store.reauthError === null) throw new Error('test setup: expected a re-auth error');

    await store.toggle('outlook', 'send', NOW);

    expect({ reauthTarget: store.reauthTarget, reauthError: store.reauthError }).toStrictEqual({
      reauthTarget: { tool: 'outlook', action: 'send' },
      reauthError: null,
    });
  });
});

// --- confirmReauth --------------------------------------------------------

describe('criticalPermissionsStore confirmReauth', () => {
  it('does nothing when no re-auth target is open', async () => {
    const store = await loadedStore();

    const outcome = await outcomeOf(store.confirmReauth(PASSWORD));

    expect({
      outcome,
      writes: writeCalls(),
      reauthTarget: store.reauthTarget,
      reauthError: store.reauthError,
      reauthBusy: store.reauthBusy,
    }).toStrictEqual({
      outcome: 'resolved',
      writes: { promote: 0, demote: 0, cancel: 0 },
      reauthTarget: null,
      reauthError: null,
      reauthBusy: false,
    });
  });

  it('promotes the target with the password and closes the prompt on success', async () => {
    mockedPromote.mockResolvedValueOnce(stateOf('gmail', 'send', 'deny', NOW));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    await store.confirmReauth(PASSWORD);

    expect({
      promote: mockedPromote.mock.calls,
      reauthTarget: store.reauthTarget,
      reauthError: store.reauthError,
      reauthBusy: store.reauthBusy,
      row: store.getState('gmail', 'send'),
    }).toStrictEqual({
      promote: [['gmail', 'send', PASSWORD]],
      reauthTarget: null,
      reauthError: null,
      reauthBusy: false,
      row: { state: 'deny', pendingAt: NOW },
    });
  });

  it('shows a success toast after a successful promotion', async () => {
    mockedPromote.mockResolvedValueOnce(stateOf('outlook', 'send', 'deny', NOW));
    const store = await loadedStore();
    await store.toggle('outlook', 'send', NOW);

    await store.confirmReauth(PASSWORD);

    const kinds = useToastStore().toasts.map((toast) => toast.kind);
    expect({ promoted: mockedPromote.mock.calls.length, kinds }).toEqual({ promoted: 1, kinds: ['success'] });
  });

  it('stores a returned "confirm" state (already promoted) and closes the prompt', async () => {
    mockedPromote.mockResolvedValueOnce(stateOf('gmail', 'send', 'confirm', null));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    await store.confirmReauth(PASSWORD);

    expect({ row: store.getState('gmail', 'send'), reauthTarget: store.reauthTarget }).toStrictEqual({
      row: { state: 'confirm', pendingAt: null },
      reauthTarget: null,
    });
  });

  it('on a 403 sets the wrong-password error, keeps the prompt open and does not throw', async () => {
    mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    const outcome = await outcomeOf(store.confirmReauth('wrong-password'));

    expect({
      outcome,
      promote: mockedPromote.mock.calls,
      reauthError: store.reauthError,
      reauthTarget: store.reauthTarget,
      reauthBusy: store.reauthBusy,
      row: store.getState('gmail', 'send'),
    }).toStrictEqual({
      outcome: 'resolved',
      promote: [['gmail', 'send', 'wrong-password']],
      reauthError: wrongPasswordText(),
      reauthTarget: { tool: 'gmail', action: 'send' },
      reauthBusy: false,
      row: { state: 'deny', pendingAt: null },
    });
  });

  it('shows no success toast after a refused (403) re-auth', async () => {
    mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    await store.confirmReauth('wrong-password');

    expect({
      promoted: mockedPromote.mock.calls.length,
      success: useToastStore().toasts.some((toast) => toast.kind === 'success'),
    }).toEqual({ promoted: 1, success: false });
  });

  it.each([
    ['a 500', () => new ApiError(500, 'Internal Server Error', 'Internal Server Error')],
    ['a 429 rate limit', () => new ApiError(429, 'Too Many Requests', 'Rate limit exceeded')],
    ['a 404 not promotable', () => new ApiError(404, 'Not Found', 'Not a promotable permission')],
    ['a network failure', () => new TypeError('Failed to fetch')],
  ] as Array<[string, () => Error]>)(
    'on %s sets the generic failure error, keeps the prompt open and does not throw',
    async (_label, makeError) => {
      mockedPromote.mockRejectedValueOnce(makeError());
      const store = await loadedStore();
      await store.toggle('outlook_calendar', 'update', NOW);

      const outcome = await outcomeOf(store.confirmReauth(PASSWORD));

      expect({
        outcome,
        promoted: mockedPromote.mock.calls.length,
        reauthError: store.reauthError,
        reauthTarget: store.reauthTarget,
        reauthBusy: store.reauthBusy,
      }).toStrictEqual({
        outcome: 'resolved',
        promoted: 1,
        reauthError: failedText(),
        reauthTarget: { tool: 'outlook_calendar', action: 'update' },
        reauthBusy: false,
      });
    },
  );

  it('clears the error and closes the prompt when a retry after a wrong password succeeds', async () => {
    mockedPromote
      .mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED))
      .mockResolvedValueOnce(stateOf('gmail', 'send', 'deny', NOW));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);
    await store.confirmReauth('wrong-password');

    await store.confirmReauth(PASSWORD);

    expect({
      promote: mockedPromote.mock.calls,
      reauthError: store.reauthError,
      reauthTarget: store.reauthTarget,
      row: store.getState('gmail', 'send'),
    }).toStrictEqual({
      promote: [
        ['gmail', 'send', 'wrong-password'],
        ['gmail', 'send', PASSWORD],
      ],
      reauthError: null,
      reauthTarget: null,
      row: { state: 'deny', pendingAt: NOW },
    });
  });

  it('is busy while the promotion is in flight and not busy after it succeeds', async () => {
    const pending = deferred<CriticalPermissionPatchResponse>();
    mockedPromote.mockReturnValueOnce(pending.promise);
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    const run = store.confirmReauth(PASSWORD);
    const during = store.reauthBusy;
    pending.resolve(stateOf('gmail', 'send', 'deny', NOW));
    await run;

    expect({ during, after: store.reauthBusy }).toStrictEqual({ during: true, after: false });
  });

  it('is busy while the promotion is in flight and not busy after it fails', async () => {
    const pending = deferred<CriticalPermissionPatchResponse>();
    mockedPromote.mockReturnValueOnce(pending.promise);
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    const run = outcomeOf(store.confirmReauth(PASSWORD));
    const during = store.reauthBusy;
    pending.reject(new ApiError(403, 'Forbidden', REAUTH_FAILED));
    await run;

    expect({ during, after: store.reauthBusy }).toStrictEqual({ during: true, after: false });
  });
});

// --- the password is never stored -----------------------------------------

describe('criticalPermissionsStore never keeps the password', () => {
  it('holds the password in no store state while the promotion is in flight', async () => {
    const pending = deferred<CriticalPermissionPatchResponse>();
    mockedPromote.mockReturnValueOnce(pending.promise);
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    const run = store.confirmReauth(PASSWORD);
    const leakedDuring = containsString(store.$state, PASSWORD);
    pending.resolve(stateOf('gmail', 'send', 'deny', NOW));
    await run;

    expect({ promoted: mockedPromote.mock.calls.length, leakedDuring }).toEqual({ promoted: 1, leakedDuring: false });
  });

  it.each([
    ['success', () => mockedPromote.mockResolvedValueOnce(stateOf('gmail', 'send', 'deny', NOW))],
    ['a 403', () => mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED))],
    ['a 500', () => mockedPromote.mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'))],
  ] as Array<[string, () => void]>)('holds the password in no store or toast state after %s', async (_label, arrange) => {
    arrange();
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);

    await outcomeOf(store.confirmReauth(PASSWORD));

    expect({
      promoted: mockedPromote.mock.calls.length,
      inStore: containsString(store.$state, PASSWORD),
      inToasts: containsString(useToastStore().$state, PASSWORD),
    }).toEqual({ promoted: 1, inStore: false, inToasts: false });
  });
});

// --- cancelReauth ---------------------------------------------------------

describe('criticalPermissionsStore cancelReauth', () => {
  it('closes an open prompt and clears its error without a request', async () => {
    mockedPromote.mockRejectedValueOnce(new ApiError(403, 'Forbidden', REAUTH_FAILED));
    const store = await loadedStore();
    await store.toggle('gmail', 'send', NOW);
    await store.confirmReauth('wrong-password');
    if (store.reauthError === null) throw new Error('test setup: expected a re-auth error');

    store.cancelReauth();

    expect({
      reauthTarget: store.reauthTarget,
      reauthError: store.reauthError,
      writes: writeCalls(),
      row: store.getState('gmail', 'send'),
    }).toStrictEqual({
      reauthTarget: null,
      reauthError: null,
      writes: { promote: 1, demote: 0, cancel: 0 },
      row: { state: 'deny', pendingAt: null },
    });
  });

  it('closes a freshly opened prompt without any request', async () => {
    const store = await loadedStore();
    await store.toggle('outlook', 'send', NOW);

    store.cancelReauth();

    expect({ reauthTarget: store.reauthTarget, writes: writeCalls() }).toStrictEqual({
      reauthTarget: null,
      writes: { promote: 0, demote: 0, cancel: 0 },
    });
  });

  it('is a no-op when no prompt is open', () => {
    const store = useCriticalPermissionsStore();

    store.cancelReauth();

    expect({ reauthTarget: store.reauthTarget, reauthError: store.reauthError, writes: writeCalls() }).toStrictEqual({
      reauthTarget: null,
      reauthError: null,
      writes: { promote: 0, demote: 0, cancel: 0 },
    });
  });
});

// --- promote --------------------------------------------------------------

describe('criticalPermissionsStore promote', () => {
  it('calls the API with the tool, the action and the password', async () => {
    mockedPromote.mockResolvedValueOnce(stateOf('gmail', 'send', 'deny', NOW));
    const store = await loadedStore();

    await store.promote('gmail', 'send', PASSWORD);

    expect({ calls: mockedPromote.mock.calls, row: store.getState('gmail', 'send') }).toStrictEqual({
      calls: [['gmail', 'send', PASSWORD]],
      row: { state: 'deny', pendingAt: NOW },
    });
  });

  it('on a refusal passes the password, rethrows the error and keeps deny', async () => {
    const refusal = new ApiError(403, 'Forbidden', REAUTH_FAILED);
    mockedPromote.mockRejectedValueOnce(refusal);
    const store = await loadedStore();

    const thrown = await outcomeOf(store.promote('outlook', 'send', 'wrong-password'));

    expect({
      thrown,
      calls: mockedPromote.mock.calls,
      row: store.getState('outlook', 'send'),
    }).toStrictEqual({
      thrown: refusal,
      calls: [['outlook', 'send', 'wrong-password']],
      row: { state: 'deny', pendingAt: null },
    });
  });
});
