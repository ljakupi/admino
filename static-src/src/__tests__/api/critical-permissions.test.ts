/**
 * Critical-permissions API client tests (issue #149).
 *
 * The bearer-token re-auth is gone (password re-auth comes with #161) and the
 * backend refuses promotions with 403 until then. `promoteCriticalPermission`
 * takes only (tool, action) and sends a PATCH with no body; a 403 surfaces as
 * an `ApiError` carrying the backend's message. `fetch` is stubbed; nothing
 * touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import { promoteCriticalPermission } from '@/api/critical-permissions';

const UNAVAILABLE = 'Critical permission promotions are temporarily unavailable.';

const fetchMock = vi.fn<typeof fetch>();

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 403 ? 'Forbidden' : 'OK',
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

describe('promoteCriticalPermission', () => {
  it('sends PATCH /api/critical-permissions/{tool}/{action} with no body', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { tool: 'gmail', action: 'send', state: 'deny', pending_at: null }),
    );

    await promoteCriticalPermission('gmail', 'send');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect({ url, method: init?.method, body: init?.body }).toEqual({
      url: '/api/critical-permissions/gmail/send',
      method: 'PATCH',
      body: undefined,
    });
  });

  it('rejects a refused (403) promotion with an ApiError carrying the backend message', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: UNAVAILABLE }));

    const error = await promoteCriticalPermission('outlook', 'send').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      message: (error as ApiError).message,
      body: fetchMock.mock.calls[0][1]?.body,
    }).toEqual({ status: 403, message: UNAVAILABLE, body: undefined });
  });
});
