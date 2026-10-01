/**
 * Permissions API client tests (issue #161: permissions per organization).
 *
 * The permission matrix is per organization now. The old `/api/permissions`
 * route is gone (404/405), and `@/api/permissions` wraps:
 * - `getPermissions()` -> `GET /api/org/permissions` (the caller's org matrix,
 *   Org Admin only; anyone else gets a 403),
 * - `patchPermission(patch)` -> `PATCH /api/org/permissions` with exactly the
 *   JSON-encoded patch as the body,
 * - `getPermissionsSummary()` -> `GET /api/permissions/summary` (read-only
 *   effective states for every member role: allow / confirm / deny /
 *   disabled).
 * Every call goes through `fetchJson`, so it sends the session cookie
 * (`credentials: 'same-origin'`), and a non-2xx rejects with an `ApiError`
 * carrying the status and the backend's `detail`. `fetch` is stubbed; nothing
 * touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import { getPermissions, getPermissionsSummary, patchPermission } from '@/api/permissions';
import type {
  PermissionPatchRequest,
  PermissionsResponse,
  PermissionsSummaryResponse,
} from '@/api/types';

const fetchMock = vi.fn<typeof fetch>();

const MATRIX: PermissionsResponse = {
  permissions: [
    { tool: 'gmail', action: 'list', permission: 'allow' },
    { tool: 'gmail', action: 'send', permission: 'deny' },
    { tool: 'memory', action: 'set', permission: 'confirm' },
  ],
};

const SUMMARY: PermissionsSummaryResponse = {
  permissions: [
    { tool: 'gmail', action: 'list', state: 'allow' },
    { tool: 'gmail', action: 'send', state: 'confirm' },
    { tool: 'memory', action: 'delete', state: 'deny' },
    { tool: 'onedrive', action: 'read', state: 'disabled' },
  ],
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 403 ? 'Forbidden' : status === 400 ? 'Bad Request' : 'OK',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** The (url, method, body, credentials) of the only fetch call made. */
function onlyRequest(): { url: unknown; method: unknown; body: unknown; credentials: unknown } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0];
  return { url, method: init?.method ?? 'GET', body: init?.body, credentials: init?.credentials };
}

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

describe('getPermissions', () => {
  it('sends GET /api/org/permissions with the session cookie and no body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MATRIX));

    await getPermissions();

    expect(onlyRequest()).toEqual({
      url: '/api/org/permissions',
      method: 'GET',
      body: undefined,
      credentials: 'same-origin',
    });
  });

  it('resolves the parsed org matrix', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MATRIX));

    const result = await getPermissions();

    expect({ url: fetchMock.mock.calls[0][0], result }).toEqual({ url: '/api/org/permissions', result: MATRIX });
  });

  it('rejects a 403 (not an Org Admin) with an ApiError carrying the backend detail', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'Forbidden' }));

    const error = await getPermissions().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect({
      url: fetchMock.mock.calls[0][0],
      status: (error as ApiError).status,
      message: (error as ApiError).message,
    }).toEqual({ url: '/api/org/permissions', status: 403, message: 'Forbidden' });
  });
});

describe('patchPermission', () => {
  it('sends PATCH /api/org/permissions with exactly the JSON-encoded patch', async () => {
    const patch: PermissionPatchRequest = { tool: 'memory', action: 'set', permission: 'allow' };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MATRIX));

    await patchPermission(patch);

    expect(onlyRequest()).toEqual({
      url: '/api/org/permissions',
      method: 'PATCH',
      body: '{"tool":"memory","action":"set","permission":"allow"}',
      credentials: 'same-origin',
    });
  });

  it('resolves the org matrix the backend returns after the change', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MATRIX));

    const result = await patchPermission({ tool: 'gmail', action: 'list', permission: 'allow' });

    expect({ url: fetchMock.mock.calls[0][0], result }).toEqual({ url: '/api/org/permissions', result: MATRIX });
  });

  it('rejects a hardcoded-denial refusal (400) with an ApiError carrying the backend detail', async () => {
    const detail = 'This tool/action pair is a hardcoded denial and cannot be changed.';
    fetchMock.mockResolvedValueOnce(jsonResponse(400, { detail }));

    const error = await patchPermission({ tool: 'gmail', action: 'delete', permission: 'allow' }).catch(
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(ApiError);
    expect({
      url: fetchMock.mock.calls[0][0],
      status: (error as ApiError).status,
      message: (error as ApiError).message,
    }).toEqual({ url: '/api/org/permissions', status: 400, message: detail });
  });
});

describe('getPermissionsSummary', () => {
  it('sends GET /api/permissions/summary with the session cookie and no body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SUMMARY));

    await getPermissionsSummary();

    expect(onlyRequest()).toEqual({
      url: '/api/permissions/summary',
      method: 'GET',
      body: undefined,
      credentials: 'same-origin',
    });
  });

  it('resolves the parsed summary, disabled entries included', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SUMMARY));

    expect(await getPermissionsSummary()).toEqual(SUMMARY);
  });

  it('rejects a 403 (Super Admin) with an ApiError carrying the status', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'Forbidden' }));

    const error = await getPermissionsSummary().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
  });
});

describe('permissions API never targets the removed routes', () => {
  it('uses no /api/permissions path other than the summary', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(200, MATRIX));

    await Promise.allSettled([
      getPermissions(),
      patchPermission({ tool: 'gmail', action: 'list', permission: 'allow' }),
      getPermissionsSummary(),
    ]);

    const urls = fetchMock.mock.calls.map(([url]) => String(url));
    expect(urls.filter((url) => url === '/api/permissions' || url.startsWith('/api/permissions?'))).toEqual([]);
    expect(urls).toEqual(['/api/org/permissions', '/api/org/permissions', '/api/permissions/summary']);
  });
});
