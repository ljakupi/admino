/**
 * Auth API client tests (issue #155: auth pages and role-aware app shell).
 *
 * `@/api/auth` wraps the public and session auth endpoints for the Login,
 * Forgot password, Reset password and Accept invitation pages and the auth
 * store: `login`, `logout`, `getMe`, `requestPasswordReset`,
 * `confirmPasswordReset`, `getInvitation` and `acceptInvitation`. Every call
 * goes through `fetchJson`, so it sends the session cookie
 * (`credentials: 'same-origin'`) and never an `Authorization` header. The
 * 202/204 endpoints resolve `undefined`; errors surface as `ApiError` with the
 * backend status (and `reason` for a 422 password policy error).
 *
 * The invitation token (from the emailed link's fragment) goes into the URL
 * path, so it is percent-encoded into exactly one path segment: a token can
 * never add a segment, a query or a fragment.
 *
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import {
  acceptInvitation,
  confirmPasswordReset,
  getInvitation,
  getMe,
  login,
  logout,
  requestPasswordReset,
} from '@/api/auth';
import type { InvitationDetails, MeResponse } from '@/api/types';

const fetchMock = vi.fn<typeof fetch>();

const BASE = 'http://admino.test';
const TOKEN = 'k3Jd8_Xq-2mPz7Lw9vRt4NcY6hBf1GsQa5EuWo0TiZy';
const EMAIL = 'alice@example.ch';
const PASSWORD = 'correct horse battery staple';

const ME: MeResponse = {
  user_id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
  kind: 'member',
  org_id: '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71',
  role: 'editor',
  ui_language: 'de',
  response_language: null,
};

const INVITATION: InvitationDetails = {
  org_name: 'Muster AG',
  role: 'viewer',
  email: 'bob@example.ch',
};

function jsonResponse(status: number, body: unknown, statusText = ''): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText,
    headers: { 'Content-Type': 'application/json' },
  });
}

function emptyResponse(status: number): Response {
  return new Response(null, { status });
}

/** The URL and RequestInit of the only fetch call. */
function sent(): { url: string; init: RequestInit } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [input, init] = fetchMock.mock.calls[0];
  return { url: String(input), init: init ?? {} };
}

function methodOf(init: RequestInit): string {
  return (init.method ?? 'GET').toUpperCase();
}

function bodyOf(init: RequestInit): unknown {
  return typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
}

/** Awaits `promise`, which must reject with an ApiError, and returns it. */
async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.then(
    () => {
      throw new Error('expected the promise to reject');
    },
    (e: unknown) => e,
  );
  if (!(error instanceof ApiError)) throw new Error(`expected an ApiError, got ${String(error)}`);
  return error;
}

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

// --- Request formation ----------------------------------------------------

describe('auth api request formation', () => {
  const calls: Array<[string, () => Promise<unknown>, Response, { method: string; url: string; body: unknown }]> = [
    [
      'login',
      () => login(EMAIL, PASSWORD),
      emptyResponse(204),
      { method: 'POST', url: '/api/auth/login', body: { email: EMAIL, password: PASSWORD } },
    ],
    [
      'requestPasswordReset',
      () => requestPasswordReset(EMAIL),
      emptyResponse(202),
      { method: 'POST', url: '/api/auth/password-reset', body: { email: EMAIL } },
    ],
    [
      'confirmPasswordReset',
      () => confirmPasswordReset(TOKEN, PASSWORD),
      emptyResponse(204),
      {
        method: 'POST',
        url: '/api/auth/password-reset/confirm',
        body: { token: TOKEN, new_password: PASSWORD },
      },
    ],
    [
      'acceptInvitation',
      () => acceptInvitation(TOKEN, 'Bob Muster', PASSWORD),
      emptyResponse(204),
      {
        method: 'POST',
        url: `/api/auth/invitations/${TOKEN}/accept`,
        body: { name: 'Bob Muster', password: PASSWORD },
      },
    ],
  ];

  it.each(calls)('%s sends the method, URL and exact JSON body', async (_name, call, response, expected) => {
    fetchMock.mockResolvedValueOnce(response);

    await call();

    const { url, init } = sent();
    expect({ method: methodOf(init), url, body: bodyOf(init) }).toEqual(expected);
  });

  it('logout sends POST /api/auth/logout', async () => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await logout();

    const { url, init } = sent();
    expect({ method: methodOf(init), url }).toEqual({ method: 'POST', url: '/api/auth/logout' });
  });

  it('getMe sends GET /api/auth/me', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ME));

    await getMe();

    const { url, init } = sent();
    expect({ method: methodOf(init), url }).toEqual({ method: 'GET', url: '/api/auth/me' });
  });

  it('getInvitation sends GET /api/auth/invitations/{token}', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, INVITATION));

    await getInvitation(TOKEN);

    const { url, init } = sent();
    expect({ method: methodOf(init), url }).toEqual({ method: 'GET', url: `/api/auth/invitations/${TOKEN}` });
  });

  const everyCall: Array<[string, () => Promise<unknown>, () => Response]> = [
    ['login', () => login(EMAIL, PASSWORD), () => emptyResponse(204)],
    ['logout', () => logout(), () => emptyResponse(204)],
    ['getMe', () => getMe(), () => jsonResponse(200, ME)],
    ['requestPasswordReset', () => requestPasswordReset(EMAIL), () => emptyResponse(202)],
    ['confirmPasswordReset', () => confirmPasswordReset(TOKEN, PASSWORD), () => emptyResponse(204)],
    ['getInvitation', () => getInvitation(TOKEN), () => jsonResponse(200, INVITATION)],
    ['acceptInvitation', () => acceptInvitation(TOKEN, 'Bob', PASSWORD), () => emptyResponse(204)],
  ];

  it.each(everyCall)(
    "%s sends the session cookie (credentials: 'same-origin') and no Authorization header",
    async (_name, call, response) => {
      localStorage.setItem('admino_auth_token', 'legacy-bearer-token');
      fetchMock.mockResolvedValueOnce(response());

      await call();

      const { init } = sent();
      expect({
        credentials: init.credentials,
        authorization: new Headers(init.headers).has('authorization'),
      }).toEqual({ credentials: 'same-origin', authorization: false });
    },
  );
});

// --- Resolved values ------------------------------------------------------

describe('auth api resolved values', () => {
  it.each([
    ['login', () => login(EMAIL, PASSWORD), 204],
    ['logout', () => logout(), 204],
    ['requestPasswordReset', () => requestPasswordReset(EMAIL), 202],
    ['confirmPasswordReset', () => confirmPasswordReset(TOKEN, PASSWORD), 204],
    ['acceptInvitation', () => acceptInvitation(TOKEN, 'Bob', PASSWORD), 204],
  ] as Array<[string, () => Promise<unknown>, number]>)(
    '%s resolves undefined on its bodiless %i',
    async (_name, call, status) => {
      fetchMock.mockResolvedValueOnce(emptyResponse(status));

      await expect(call()).resolves.toBeUndefined();
    },
  );

  it('getMe resolves the parsed MeResponse', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ME));

    await expect(getMe()).resolves.toEqual(ME);
  });

  it('getInvitation resolves the parsed InvitationDetails', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, INVITATION));

    await expect(getInvitation(TOKEN)).resolves.toEqual(INVITATION);
  });
});

// --- Errors ---------------------------------------------------------------

describe('auth api errors', () => {
  it('login rejects a wrong password with ApiError 401 carrying the generic backend message', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Invalid email or password' }, 'Unauthorized'));

    const error = await apiErrorOf(login(EMAIL, 'wrong-password-123'));

    expect({ status: error.status, message: error.message }).toEqual({
      status: 401,
      message: 'Invalid email or password',
    });
  });

  it('login rejects a rate-limited attempt with ApiError 429', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { detail: 'Too many requests' }, 'Too Many Requests'));

    expect((await apiErrorOf(login(EMAIL, PASSWORD))).status).toBe(429);
  });

  it('getMe rejects with ApiError 401 without a session', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }, 'Unauthorized'));

    expect((await apiErrorOf(getMe())).status).toBe(401);
  });

  it('requestPasswordReset rejects a rate-limited request with ApiError 429', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { detail: 'Too many requests' }, 'Too Many Requests'));

    expect((await apiErrorOf(requestPasswordReset(EMAIL))).status).toBe(429);
  });

  it('confirmPasswordReset rejects an invalid link with ApiError 400', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, { detail: 'This reset link is invalid or has expired.' }, 'Bad Request'),
    );

    expect((await apiErrorOf(confirmPasswordReset(TOKEN, PASSWORD))).status).toBe(400);
  });

  it('confirmPasswordReset rejects a policy failure with ApiError 422 and its reason', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { detail: 'This password is too common.', reason: 'common' }, 'Unprocessable Entity'),
    );

    const error = await apiErrorOf(confirmPasswordReset(TOKEN, 'password1234'));

    expect({ status: error.status, reason: error.reason }).toEqual({ status: 422, reason: 'common' });
  });

  it('getInvitation rejects an invalid link with ApiError 404', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(404, { detail: 'This invitation link is invalid or has expired.' }, 'Not Found'),
    );

    expect((await apiErrorOf(getInvitation(TOKEN))).status).toBe(404);
  });

  it('acceptInvitation rejects a policy failure with ApiError 422 and its reason', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { detail: 'The password must not be your email address.', reason: 'equals_email' }),
    );

    const error = await apiErrorOf(acceptInvitation(TOKEN, 'Bob', 'bob@example.ch'));

    expect({ status: error.status, reason: error.reason }).toEqual({ status: 422, reason: 'equals_email' });
  });

  it('acceptInvitation rejects an invalid name (pydantic detail list) with ApiError 422 and no reason', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { detail: [{ loc: ['body', 'name'], msg: 'Value error, bad name', type: 'value_error' }] }),
    );

    const error = await apiErrorOf(acceptInvitation(TOKEN, '   ', PASSWORD));

    expect({ status: error.status, reason: error.reason }).toEqual({ status: 422, reason: undefined });
  });
});

// --- Token encoding -------------------------------------------------------

describe('auth api invitation token encoding', () => {
  const hostileTokens = [
    'a/b',
    'x?y=1',
    'a#b',
    '../../api/settings',
    '..%2F..%2Fapi',
    'tok en',
    'a&b=c',
    '..\\..\\api',
  ];

  /** The path segments after `/api/auth/invitations/`, plus the query and fragment, as the browser resolves the URL. */
  function resolved(url: string): { tail: string[]; search: string; hash: string } {
    const parsed = new URL(url, BASE);
    const prefix = '/api/auth/invitations/';
    if (!parsed.pathname.startsWith(prefix)) throw new Error(`escaped the invitations path: ${parsed.pathname}`);
    return { tail: parsed.pathname.slice(prefix.length).split('/'), search: parsed.search, hash: parsed.hash };
  }

  it.each(hostileTokens)('getInvitation puts the token %j into one encoded path segment', async (token) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, INVITATION));

    await getInvitation(token);

    const { url } = sent();
    expect({ url, ...resolved(url) }).toEqual({
      url: `/api/auth/invitations/${encodeURIComponent(token)}`,
      tail: [encodeURIComponent(token)],
      search: '',
      hash: '',
    });
  });

  it.each(hostileTokens)('acceptInvitation puts the token %j into one encoded path segment', async (token) => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await acceptInvitation(token, 'Bob', PASSWORD);

    const { url } = sent();
    expect({ url, ...resolved(url) }).toEqual({
      url: `/api/auth/invitations/${encodeURIComponent(token)}/accept`,
      tail: [encodeURIComponent(token), 'accept'],
      search: '',
      hash: '',
    });
  });

  it('never puts the token into the accept request body', async () => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await acceptInvitation(TOKEN, 'Bob', PASSWORD);

    expect(String(sent().init.body)).not.toContain(TOKEN);
  });
});
