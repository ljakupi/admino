/**
 * SSE client tests (issue #149: server-side sessions replace the bearer token).
 *
 * `EventSource` can't set headers, so the old client put the bearer token in
 * a `token` query parameter. With the `admino_session` cookie (sent by the
 * browser on the same-origin stream) `openEventStream` must build
 * `/api/events?session_id=…` with no token parameter and never read the old
 * `admino_auth_token` localStorage key. `EventSource` is stubbed; nothing
 * touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { openEventStream } from '@/api/events';

const LEGACY_TOKEN_KEY = 'admino_auth_token';
const LEGACY_TOKEN = 'legacy-bearer-token-0123456789-abcdef';

/** Records every EventSource the client opens. */
class FakeEventSource {
  static opened: FakeEventSource[] = [];
  readonly url: string;
  onerror: (() => void) | null = null;

  constructor(url: string | URL) {
    this.url = String(url);
    FakeEventSource.opened.push(this);
  }

  addEventListener(): void {}

  close(): void {}
}

/** The URL of the only stream opened. */
function openedUrl(): URL {
  expect(FakeEventSource.opened).toHaveLength(1);
  return new URL(FakeEventSource.opened[0].url, 'http://localhost');
}


/**
 * A stand-in localStorage that records every key read. happy-dom's Storage
 * can't be spied through Storage.prototype, so the global is replaced.
 */
function recordingStorage(initial: Record<string, string>): { storage: Storage; reads: string[] } {
  const data = new Map(Object.entries(initial));
  const reads: string[] = [];
  const storage: Storage = {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key: string) => {
      reads.push(key);
      return data.get(key) ?? null;
    },
    key: (index: number) => [...data.keys()][index] ?? null,
    removeItem: (key: string) => {
      data.delete(key);
    },
    setItem: (key: string, value: string) => {
      data.set(key, String(value));
    },
  };
  return { storage, reads };
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem(LEGACY_TOKEN_KEY, LEGACY_TOKEN);
  FakeEventSource.opened = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});

describe('openEventStream session-cookie auth', () => {
  it('opens /api/events?session_id=… and nothing else when a legacy token is stored', () => {
    openEventStream('s-abc_123', {});

    expect(FakeEventSource.opened.map((source) => source.url)).toEqual([
      '/api/events?session_id=s-abc_123',
    ]);
  });

  it('sends no token query parameter', () => {
    openEventStream('s-abc_123', {});

    expect(openedUrl().searchParams.has('token')).toBe(false);
  });

  it('never reads the legacy admino_auth_token key', () => {
    const { storage, reads } = recordingStorage({ [LEGACY_TOKEN_KEY]: LEGACY_TOKEN });
    vi.stubGlobal('localStorage', storage);

    openEventStream('s-abc_123', {});

    expect(reads).not.toContain(LEGACY_TOKEN_KEY);
  });
});
