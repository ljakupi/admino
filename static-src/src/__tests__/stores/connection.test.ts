/**
 * Connection store tests (issue #21).
 *
 * Covers health checking, the idle/working/awaiting/offline state machine,
 * offline detection, reconnection and the 10 s health-polling loop.
 * `fetch` is stubbed globally — no network access. Polling uses fake timers.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { useConnectionStore, type ConnectionState } from '@/stores/connection';

type HealthResponseLike = Pick<Response, 'ok' | 'status' | 'json'>;
type FetchLike = (input: string) => Promise<HealthResponseLike>;

const POLL_INTERVAL_MS = 10_000;

function healthyResponse(): HealthResponseLike {
  return { ok: true, status: 200, json: async () => ({ status: 'ok' }) };
}

function unhealthyResponse(status = 503): HealthResponseLike {
  return { ok: false, status, json: async () => ({ detail: 'Service Unavailable' }) };
}

function stubFetch(impl: FetchLike) {
  const fetchMock = vi.fn<FetchLike>(impl);
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** Let pending promise chains (fetch → json → state update) settle. */
async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

/** Put the store into a given state through its public API (from 'idle'). */
function driveTo(target: Exclude<ConnectionState, 'offline'>) {
  const store = useConnectionStore();
  store.state = 'idle';
  if (target === 'working' || target === 'awaiting') store.setWorking();
  if (target === 'awaiting') store.setAwaiting();
  return store;
}

beforeEach(() => {
  localStorage.clear();
  setActivePinia(createPinia());
});

describe('connectionStore initial state', () => {
  it('starts offline', () => {
    expect(useConnectionStore().state).toBe('offline');
  });
});

describe('connectionStore checkHealth', () => {
  it('requests the /health endpoint', async () => {
    const fetchMock = stubFetch(async () => healthyResponse());

    await useConnectionStore().checkHealth();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/health');
  });

  it('moves offline to idle on a healthy response', async () => {
    stubFetch(async () => healthyResponse());
    const store = useConnectionStore();

    await store.checkHealth();

    expect(store.state).toBe('idle');
  });

  it('resolves true on a healthy response', async () => {
    stubFetch(async () => healthyResponse());

    await expect(useConnectionStore().checkHealth()).resolves.toBe(true);
  });

  it('goes offline and resolves false on a non-ok response', async () => {
    stubFetch(async () => unhealthyResponse(503));
    const store = driveTo('idle');

    const result = await store.checkHealth();

    expect(result).toBe(false);
    expect(store.state).toBe('offline');
  });

  it('goes offline and resolves false when the network request fails', async () => {
    stubFetch(async () => {
      throw new TypeError('Failed to fetch');
    });
    const store = driveTo('idle');

    const result = await store.checkHealth();

    expect(result).toBe(false);
    expect(store.state).toBe('offline');
  });

  it.each(['working', 'awaiting'] as const)(
    'does not clobber an in-progress %s state on a healthy response',
    async (inProgress) => {
      stubFetch(async () => healthyResponse());
      const store = driveTo(inProgress);

      await store.checkHealth();

      expect(store.state).toBe(inProgress);
    },
  );
});

describe('connectionStore transitions', () => {
  it('goes idle → working → idle', () => {
    const store = driveTo('idle');
    const seen: ConnectionState[] = [store.state];

    store.setWorking();
    seen.push(store.state);
    store.setIdle();
    seen.push(store.state);

    expect(seen).toEqual(['idle', 'working', 'idle']);
  });

  it('goes idle → working → awaiting → working → idle', () => {
    const store = driveTo('idle');
    const seen: ConnectionState[] = [store.state];

    store.setWorking();
    seen.push(store.state);
    store.setAwaiting();
    seen.push(store.state);
    store.setWorking();
    seen.push(store.state);
    store.setIdle();
    seen.push(store.state);

    expect(seen).toEqual(['idle', 'working', 'awaiting', 'working', 'idle']);
  });
});

describe('connectionStore offline detection', () => {
  it('goes offline when a health check fails during a run', async () => {
    stubFetch(async () => {
      throw new TypeError('Failed to fetch');
    });
    const store = driveTo('working');

    await store.checkHealth();

    expect(store.state).toBe('offline');
  });

  it.each(['setWorking', 'setAwaiting', 'setIdle'] as const)(
    'ignores %s while offline',
    (setter) => {
      const store = useConnectionStore();
      store.state = 'offline';

      store[setter]();

      expect(store.state).toBe('offline');
    },
  );
});

describe('connectionStore reconnection', () => {
  it('returns to idle when health recovers after going offline', async () => {
    let serverUp = false;
    stubFetch(async () => {
      if (!serverUp) throw new TypeError('Failed to fetch');
      return healthyResponse();
    });
    const store = driveTo('idle');
    await store.checkHealth();
    expect(store.state).toBe('offline');

    serverUp = true;
    await store.checkHealth();

    expect(store.state).toBe('idle');
  });

  it('accepts setWorking again after reconnecting', async () => {
    const store = useConnectionStore();
    store.state = 'offline';
    stubFetch(async () => healthyResponse());
    await store.checkHealth();

    store.setWorking();

    expect(store.state).toBe('working');
  });
});

describe('connectionStore polling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    useConnectionStore().stopPolling();
    vi.useRealTimers();
  });

  it('performs one health check immediately on start', () => {
    const fetchMock = stubFetch(async () => healthyResponse());

    useConnectionStore().startPolling();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('checks health once every 10 seconds', async () => {
    const fetchMock = stubFetch(async () => healthyResponse());
    useConnectionStore().startPolling();

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS - 1);
    const beforeFirstTick = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(1);
    const afterFirstTick = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    const afterSecondTick = fetchMock.mock.calls.length;

    expect([beforeFirstTick, afterFirstTick, afterSecondTick]).toEqual([1, 2, 3]);
  });

  it('stops checking after stopPolling', async () => {
    const fetchMock = stubFetch(async () => healthyResponse());
    const store = useConnectionStore();
    store.startPolling();
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    const callsBeforeStop = fetchMock.mock.calls.length;

    store.stopPolling();
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);

    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeStop);
  });

  it('allows stopPolling without a prior startPolling', () => {
    stubFetch(async () => healthyResponse());

    expect(() => useConnectionStore().stopPolling()).not.toThrow();
  });

  it('does not create duplicate timers when started twice', async () => {
    const fetchMock = stubFetch(async () => healthyResponse());
    const store = useConnectionStore();
    store.startPolling();
    store.startPolling();
    const afterStarts = fetchMock.mock.calls.length;

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    const afterFirstTick = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    const afterSecondTick = fetchMock.mock.calls.length;

    expect([afterFirstTick - afterStarts, afterSecondTick - afterFirstTick]).toEqual([1, 1]);
  });

  it('stops all checks after stopPolling when started twice', async () => {
    const fetchMock = stubFetch(async () => healthyResponse());
    const store = useConnectionStore();
    store.startPolling();
    store.startPolling();
    const callsBeforeStop = fetchMock.mock.calls.length;

    store.stopPolling();
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);

    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeStop);
  });

  it('detects going offline and coming back across polling ticks', async () => {
    let serverUp = true;
    stubFetch(async () => {
      if (!serverUp) throw new TypeError('Failed to fetch');
      return healthyResponse();
    });
    const store = useConnectionStore();
    const seen: ConnectionState[] = [];

    store.startPolling();
    await flushMicrotasks();
    seen.push(store.state);

    serverUp = false;
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    await flushMicrotasks();
    seen.push(store.state);

    serverUp = true;
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    await flushMicrotasks();
    seen.push(store.state);

    expect(seen).toEqual(['idle', 'offline', 'idle']);
  });
});
