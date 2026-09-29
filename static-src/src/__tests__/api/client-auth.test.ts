/**
 * API client tests for the auth pages (issue #155).
 *
 * Three changes to `@/api/client`, specified here (the session-cookie tests of
 * #149 stay in `client.test.ts`):
 *
 * 1. Empty success bodies: the auth endpoints answer 202 (password reset
 *    request) or 204 (login, logout, reset confirm, invitation accept) with no
 *    body. `fetchJson` resolves `undefined` for those without reading the body;
 *    any other 2xx is still parsed as JSON.
 * 2. `ApiError.reason`: an optional 4th constructor argument, filled from a
 *    top-level string `reason` of the error body only when it is a short
 *    snake_case code (`/^[a-z_]{1,40}$/`, e.g. the password policy's
 *    `too_short`). Anything else leaves it `undefined`, so a hostile or
 *    malformed body can never smuggle text through it. `message` is unchanged.
 * 3. `setUnauthorizedHandler(handler)`: a 401 from any path outside
 *    `/api/auth/` calls the registered handler exactly once and still throws
 *    the `ApiError(401)`. `/api/auth/*` paths (login, me, logout, reset,
 *    invitations), other statuses and network errors never call it. A throwing
 *    handler never replaces the `ApiError`.
 *
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ApiError, fetchJson, setUnauthorizedHandler } from '@/api/client';

const fetchMock = vi.fn<typeof fetch>();

const STATUS_TEXT: Record<number, string> = {
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  204: 'No Content',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: STATUS_TEXT[status] ?? '',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A bodiless response whose `json()` is spied, so a test can prove it was never read. */
function emptyResponse(status: number): { response: Response; jsonReads: () => number } {
  const response = new Response(null, { status, statusText: STATUS_TEXT[status] ?? '' });
  const json = vi.spyOn(response, 'json');
  return { response, jsonReads: () => json.mock.calls.length };
}

/** Awaits `promise`, which must reject, and returns the rejection reason. */
async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected the promise to reject');
    },
    (error: unknown) => error,
  );
}

/** The `reason` of the ApiError a request answered with `status` / `body` rejects with. */
async function reasonFor(status: number, body: unknown): Promise<string | undefined> {
  fetchMock.mockResolvedValueOnce(jsonResponse(status, body));
  const error = await rejectionOf(fetchJson('/api/auth/password-reset/confirm', { method: 'POST' }));
  if (!(error instanceof ApiError)) throw new Error('expected an ApiError');
  return error.reason;
}

const POLICY_DETAIL = 'The password must be at least 12 characters long.';

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

// --- 202 / 204: no body ---------------------------------------------------

describe('fetchJson empty success bodies', () => {
  it.each([202, 204])('resolves undefined for a %i without reading the body', async (status) => {
    const { response, jsonReads } = emptyResponse(status);
    fetchMock.mockResolvedValueOnce(response);

    const value = await fetchJson<unknown>('/api/auth/login', { method: 'POST', body: '{}' });

    expect({ value, jsonReads: jsonReads() }).toEqual({ value: undefined, jsonReads: 0 });
  });

  it.each([200, 201])('still parses a %i body as JSON, while a 204 resolves undefined', async (status) => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204).response);
    fetchMock.mockResolvedValueOnce(jsonResponse(status, { id: 'x', ok: true }));

    const empty = await fetchJson<unknown>('/api/auth/logout', { method: 'POST' });
    const parsed = await fetchJson<unknown>('/api/org/invitations', { method: 'POST', body: '{}' });

    expect({ empty, parsed }).toEqual({ empty: undefined, parsed: { id: 'x', ok: true } });
  });
});

// --- ApiError.reason ------------------------------------------------------

describe('ApiError reason', () => {
  it('keeps a 4th constructor argument as reason, next to status and message', () => {
    const error = new ApiError(422, 'Unprocessable Entity', POLICY_DETAIL, 'too_short');

    expect({ status: error.status, message: error.message, reason: error.reason }).toEqual({
      status: 422,
      message: POLICY_DETAIL,
      reason: 'too_short',
    });
  });

  it('fills reason and keeps the detail as message for a 422 policy error', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: POLICY_DETAIL, reason: 'too_short' }));

    const error = await rejectionOf(fetchJson('/api/auth/password-reset/confirm', { method: 'POST' }));

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      message: (error as ApiError).message,
      reason: (error as ApiError).reason,
    }).toEqual({ status: 422, message: POLICY_DETAIL, reason: 'too_short' });
  });

  it.each(['too_long', 'common', 'equals_email', 'a', 'a'.repeat(40), 'snake_case_code'])(
    'accepts the snake_case reason %j',
    async (reason) => {
      expect(await reasonFor(422, { detail: POLICY_DETAIL, reason })).toBe(reason);
    },
  );

  // Each rejected shape is checked next to a well-formed reason from the same
  // client, so the test proves the parser is active and refuses only the bad one.
  const rejectedBodies: Array<[string, unknown]> = [
    ['no reason field', { detail: POLICY_DETAIL }],
    ['a number', { detail: POLICY_DETAIL, reason: 42 }],
    ['null', { detail: POLICY_DETAIL, reason: null }],
    ['a list', { detail: POLICY_DETAIL, reason: ['too_short'] }],
    ['an object', { detail: POLICY_DETAIL, reason: { code: 'too_short' } }],
    ['an empty string', { detail: POLICY_DETAIL, reason: '' }],
    ['41 characters', { detail: POLICY_DETAIL, reason: 'a'.repeat(41) }],
    ['uppercase', { detail: POLICY_DETAIL, reason: 'Too_Short' }],
    ['a space', { detail: POLICY_DETAIL, reason: 'too short' }],
    ['a hyphen', { detail: POLICY_DETAIL, reason: 'too-short' }],
    ['a digit', { detail: POLICY_DETAIL, reason: 'too_short2' }],
    ['a trailing newline', { detail: POLICY_DETAIL, reason: 'too_short\n' }],
    ['HTML', { detail: POLICY_DETAIL, reason: '<img src=x onerror=alert(1)>' }],
    ['a nested reason only', { detail: { reason: 'too_short' } }],
    ['a pydantic detail list without reason', { detail: [{ loc: ['body', 'name'], msg: 'bad', type: 'x' }] }],
  ];

  it.each(rejectedBodies)('leaves reason undefined for %s', async (_label, body) => {
    const rejected = await reasonFor(422, body);
    const accepted = await reasonFor(422, { detail: POLICY_DETAIL, reason: 'common' });

    expect([rejected, accepted]).toEqual([undefined, 'common']);
  });

  it('keeps the detail as message when the reason is refused', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: POLICY_DETAIL, reason: 'Not A Code' }));
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: POLICY_DETAIL, reason: 'common' }));

    const refused = (await rejectionOf(fetchJson('/api/x'))) as ApiError;
    const accepted = (await rejectionOf(fetchJson('/api/x'))) as ApiError;

    expect([
      { message: refused.message, reason: refused.reason },
      { message: accepted.message, reason: accepted.reason },
    ]).toEqual([
      { message: POLICY_DETAIL, reason: undefined },
      { message: POLICY_DETAIL, reason: 'common' },
    ]);
  });

  it('leaves reason undefined for a non-JSON error body', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>oops</html>', { status: 502, statusText: 'Bad Gateway' }));
    const nonJson = (await rejectionOf(fetchJson('/api/x'))) as ApiError;
    const accepted = await reasonFor(422, { detail: POLICY_DETAIL, reason: 'equals_email' });

    expect([nonJson.status, nonJson.reason, accepted]).toEqual([502, undefined, 'equals_email']);
  });
});

// --- Global 401 handler ---------------------------------------------------

describe('fetchJson unauthorized handler', () => {
  afterEach(() => {
    setUnauthorizedHandler(null);
  });

  it('calls the handler exactly once for a 401 and still rejects with ApiError(401)', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    const error = await rejectionOf(fetchJson('/api/settings'));

    expect(error).toBeInstanceOf(ApiError);
    expect({ status: (error as ApiError).status, calls: handler.mock.calls.length }).toEqual({
      status: 401,
      calls: 1,
    });
  });

  it.each([
    '/api/settings',
    '/api/message',
    '/api/permissions',
    '/api/critical-permissions/gmail/send',
    '/api/me/sessions',
    '/api/org/users/u-1/logout',
    '/api/oauth/google/authorize',
    '/api/settings?section=llm',
  ])('calls the handler for a 401 from %s', async (path) => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    await rejectionOf(fetchJson(path));

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it.each([
    '/api/auth/login',
    '/api/auth/me',
    '/api/auth/logout',
    '/api/auth/password-reset',
    '/api/auth/password-reset/confirm',
    '/api/auth/invitations/abc',
    '/api/auth/invitations/abc/accept',
  ])('never calls the handler for a 401 from %s, but still rejects with ApiError(401)', async (path) => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Invalid email or password' }));

    const error = await rejectionOf(fetchJson(path, { method: 'POST' }));

    expect({
      apiError: error instanceof ApiError,
      status: (error as ApiError).status,
      calls: handler.mock.calls.length,
    }).toEqual({ apiError: true, status: 401, calls: 0 });
  });

  it.each([400, 403, 404, 422, 429, 500, 503])('never calls the handler for a %i', async (status) => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(jsonResponse(status, { detail: 'Nope' }));

    const error = await rejectionOf(fetchJson('/api/settings'));

    expect({ status: (error as ApiError).status, calls: handler.mock.calls.length }).toEqual({
      status,
      calls: 0,
    });
  });

  it('never calls the handler for a network error, which still rejects as is', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    const networkError = new TypeError('Failed to fetch');
    fetchMock.mockRejectedValueOnce(networkError);

    const error = await rejectionOf(fetchJson('/api/settings'));

    expect({ error, calls: handler.mock.calls.length }).toEqual({ error: networkError, calls: 0 });
  });

  it('just rejects with ApiError(401) when no handler is registered', async () => {
    setUnauthorizedHandler(null);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    const error = await rejectionOf(fetchJson('/api/settings'));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
  });

  it('stops calling a handler once it is unregistered with null', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setUnauthorizedHandler(null);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    await rejectionOf(fetchJson('/api/settings'));

    expect(handler).not.toHaveBeenCalled();
  });

  it('replaces the previous handler when a new one is registered', async () => {
    const first = vi.fn();
    const second = vi.fn();
    setUnauthorizedHandler(first);
    setUnauthorizedHandler(second);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    await rejectionOf(fetchJson('/api/settings'));

    expect([first.mock.calls.length, second.mock.calls.length]).toEqual([0, 1]);
  });

  it('calls the handler once per 401 response', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockImplementation(async () => jsonResponse(401, { detail: 'Unauthorized' }));

    await Promise.allSettled([fetchJson('/api/settings'), fetchJson('/api/permissions')]);

    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('still rejects with ApiError(401) when the handler throws', async () => {
    const handler = vi.fn(() => {
      throw new Error('handler exploded');
    });
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }));

    const error = await rejectionOf(fetchJson('/api/settings'));

    expect({
      apiError: error instanceof ApiError,
      status: (error as ApiError).status,
      calls: handler.mock.calls.length,
    }).toEqual({ apiError: true, status: 401, calls: 1 });
  });
});
