/**
 * API client tests (issue #149: server-side sessions replace the bearer token).
 *
 * The session lives in the HttpOnly `admino_session` cookie, which the browser
 * sends by itself. `fetchJson` must therefore send no `Authorization` header,
 * never read the old `admino_auth_token` localStorage key (a stale value left
 * by the old PWA must be ignored), and ask for `credentials: 'same-origin'`.
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchJson } from '@/api/client';

/** localStorage key the removed token prompt stored the bearer token under. */
const LEGACY_TOKEN_KEY = 'admino_auth_token';
const LEGACY_TOKEN = 'legacy-bearer-token-0123456789-abcdef';

const fetchMock = vi.fn<typeof fetch>();

function okJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** The RequestInit of the only fetch call. */
function sentInit(): RequestInit {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  return fetchMock.mock.calls[0][1] ?? {};
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
  fetchMock.mockReset();
  fetchMock.mockImplementation(async () => okJson({ ok: true }));
  vi.stubGlobal('fetch', fetchMock);
});

describe('fetchJson session-cookie auth', () => {
  it('sends no Authorization header even when a legacy token is stored', async () => {
    await fetchJson('/api/settings');

    expect(new Headers(sentInit().headers).has('authorization')).toBe(false);
  });

  it('never puts the legacy token anywhere in the request', async () => {
    await fetchJson('/api/settings', { method: 'PATCH', body: '{}' });

    const init = sentInit();
    const sent = JSON.stringify([...new Headers(init.headers).entries(), init.body]);
    expect(sent).not.toContain(LEGACY_TOKEN);
  });

  it('never reads the legacy admino_auth_token key', async () => {
    const { storage, reads } = recordingStorage({ [LEGACY_TOKEN_KEY]: LEGACY_TOKEN });
    vi.stubGlobal('localStorage', storage);

    await fetchJson('/api/settings');

    expect(reads).not.toContain(LEGACY_TOKEN_KEY);
  });

  it("sends the session cookie with credentials: 'same-origin'", async () => {
    await fetchJson('/api/settings');

    expect(sentInit().credentials).toBe('same-origin');
  });

  it("keeps credentials: 'same-origin' when the caller passes a method and body", async () => {
    await fetchJson('/api/critical-permissions/gmail/send', { method: 'PATCH', body: '{}' });

    expect(sentInit().credentials).toBe('same-origin');
  });
});
