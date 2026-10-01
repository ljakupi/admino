/**
 * Critical-permissions API client tests (issue #149; issue #161: critical
 * permissions are per organization and a promotion needs password re-auth).
 *
 * The routes moved under the organization: the base is
 * `/api/org/critical-permissions` (the old `/api/critical-permissions*`
 * routes are gone).
 * - `getCriticalPermissions()` -> `GET <base>`.
 * - `promoteCriticalPermission(tool, action, password)` -> `PATCH
 *   <base>/<tool>/<action>` with the JSON body `{"password": password}` and
 *   nothing else. The password never goes into the URL.
 * - `demoteCriticalPermission(tool, action)` -> `PATCH` on the same path with
 *   NO body (demotion only reduces privilege, so no password).
 * - `cancelPendingPromotion(tool, action)` -> `DELETE <path>/pending`, no body.
 * `tool` and `action` are URI-encoded path segments. A refused re-auth (403)
 * surfaces as an `ApiError` carrying the backend's message. `fetch` is
 * stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import {
  cancelPendingPromotion,
  demoteCriticalPermission,
  getCriticalPermissions,
  promoteCriticalPermission,
} from '@/api/critical-permissions';
import type { CriticalPermissionsResponse } from '@/api/types';

const REAUTH_FAILED = 'Re-authentication failed.';
const PASSWORD = 'correct horse battery staple';

const fetchMock = vi.fn<typeof fetch>();

const LIST: CriticalPermissionsResponse = {
  permissions: [
    { tool: 'gmail', action: 'send', state: 'deny', pending_at: null },
    { tool: 'google_calendar', action: 'update', state: 'confirm', pending_at: null },
    { tool: 'outlook', action: 'send', state: 'deny', pending_at: '2026-10-01T10:00:00Z' },
    { tool: 'outlook_calendar', action: 'update', state: 'deny', pending_at: null },
  ],
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 403 ? 'Forbidden' : 'OK',
    headers: { 'Content-Type': 'application/json' },
  });
}

function stateResponse(tool = 'gmail', action = 'send'): Response {
  return jsonResponse(200, { tool, action, state: 'deny', pending_at: null });
}

/** The (url, method, body) of the only fetch call made. */
function onlyRequest(): { url: unknown; method: unknown; body: unknown } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0];
  return { url, method: init?.method ?? 'GET', body: init?.body };
}

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

describe('getCriticalPermissions', () => {
  it('sends GET /api/org/critical-permissions with no body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, LIST));

    await getCriticalPermissions();

    expect(onlyRequest()).toEqual({ url: '/api/org/critical-permissions', method: 'GET', body: undefined });
  });

  it('resolves the parsed list', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, LIST));

    const result = await getCriticalPermissions();

    expect({ url: fetchMock.mock.calls[0][0], result }).toEqual({
      url: '/api/org/critical-permissions',
      result: LIST,
    });
  });
});

describe('promoteCriticalPermission', () => {
  it('sends PATCH /api/org/critical-permissions/{tool}/{action} with exactly {"password": ...}', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse());

    await promoteCriticalPermission('gmail', 'send', PASSWORD);

    expect(onlyRequest()).toEqual({
      url: '/api/org/critical-permissions/gmail/send',
      method: 'PATCH',
      body: JSON.stringify({ password: PASSWORD }),
    });
  });

  it('JSON-encodes a password with quotes, backslashes and non-ASCII characters (only the password key)', async () => {
    const tricky = 'p"a\\ss wört}{,';
    fetchMock.mockResolvedValueOnce(stateResponse());

    await promoteCriticalPermission('outlook', 'send', tricky);

    const body = fetchMock.mock.calls[0][1]?.body;
    expect(typeof body).toBe('string');
    expect(JSON.parse(body as string)).toStrictEqual({ password: tricky });
  });

  it('never puts the password into the URL', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse());

    await promoteCriticalPermission('gmail', 'send', 'hunter2-secret');

    const url = String(fetchMock.mock.calls[0][0]);
    expect({ url, leaked: url.includes('hunter2') }).toEqual({
      url: '/api/org/critical-permissions/gmail/send',
      leaked: false,
    });
  });

  it('resolves the backend state (pending cooldown)', async () => {
    const pending = { tool: 'gmail', action: 'send', state: 'deny', pending_at: '2026-10-01T10:00:00Z' };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, pending));

    const result = await promoteCriticalPermission('gmail', 'send', PASSWORD);

    expect({ body: fetchMock.mock.calls[0][1]?.body, result }).toEqual({
      body: JSON.stringify({ password: PASSWORD }),
      result: pending,
    });
  });

  it('rejects a failed re-auth (403) with an ApiError carrying the backend message', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: REAUTH_FAILED }));

    const error = await promoteCriticalPermission('outlook', 'send', 'wrong').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      message: (error as ApiError).message,
      url: fetchMock.mock.calls[0][0],
      body: fetchMock.mock.calls[0][1]?.body,
    }).toEqual({
      status: 403,
      message: REAUTH_FAILED,
      url: '/api/org/critical-permissions/outlook/send',
      body: JSON.stringify({ password: 'wrong' }),
    });
  });
});

describe('demoteCriticalPermission', () => {
  it('sends PATCH /api/org/critical-permissions/{tool}/{action} with no body', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse('google_calendar', 'update'));

    await demoteCriticalPermission('google_calendar', 'update');

    expect(onlyRequest()).toEqual({
      url: '/api/org/critical-permissions/google_calendar/update',
      method: 'PATCH',
      body: undefined,
    });
  });
});

describe('cancelPendingPromotion', () => {
  it('sends DELETE /api/org/critical-permissions/{tool}/{action}/pending with no body', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse('outlook', 'send'));

    await cancelPendingPromotion('outlook', 'send');

    expect(onlyRequest()).toEqual({
      url: '/api/org/critical-permissions/outlook/send/pending',
      method: 'DELETE',
      body: undefined,
    });
  });
});

describe('critical-permissions path encoding', () => {
  const TOOL = 'a/b?c';
  const ACTION = '../x#y';
  const ENCODED = `/api/org/critical-permissions/${encodeURIComponent(TOOL)}/${encodeURIComponent(ACTION)}`;

  it('URI-encodes tool and action on promote', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse());

    await promoteCriticalPermission(TOOL, ACTION, PASSWORD);

    expect(fetchMock.mock.calls[0][0]).toBe(ENCODED);
  });

  it('URI-encodes tool and action on demote', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse());

    await demoteCriticalPermission(TOOL, ACTION);

    expect(fetchMock.mock.calls[0][0]).toBe(ENCODED);
  });

  it('URI-encodes tool and action on cancel', async () => {
    fetchMock.mockResolvedValueOnce(stateResponse());

    await cancelPendingPromotion(TOOL, ACTION);

    expect(fetchMock.mock.calls[0][0]).toBe(`${ENCODED}/pending`);
  });
});
