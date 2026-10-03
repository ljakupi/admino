/**
 * My account API client tests (issue #166: account self-service, the
 * profile, languages, timezone, personal instructions, password change and
 * the session list).
 *
 * `@/api/account` wraps, through `fetchJson` (so every call carries the
 * session cookie, `credentials: 'same-origin'`, never an `Authorization`
 * header, and a non-2xx answer throws an `ApiError` with `.status` and
 * `.reason`):
 * - `getMyAccount()` -> `GET /api/me` (the caller's own `MyAccount`),
 * - `patchMyAccount(patch)` -> `PATCH /api/me`, JSON body exactly the given
 *   patch (no extra keys; `response_language: null` is sent as `null`, it
 *   means "use the org default"),
 * - `changeMyPassword(current, next)` -> `POST /api/me/password`, body
 *   exactly `{"current_password", "new_password"}`, 204 resolves `undefined`,
 * - `listMySessions()` -> `GET /api/me/sessions`, resolves the `.sessions`
 *   array of the answer,
 * - `revokeMySession(id)` -> `DELETE /api/me/sessions/{id}` (204 resolves
 *   `undefined`).
 *
 * Path-injection guard: the session `id` must be a UUID
 * (`/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`);
 * anything else throws a plain `Error('Invalid session id')` (not an
 * `ApiError`) and makes NO request. A valid id is one path segment.
 *
 * A 422 password-policy answer `{"detail", "reason": "too_short"}` surfaces
 * as an `ApiError` with status 422 and that reason; a wrong current password
 * is a 403 (never a 401, which the PWA treats as "session expired"). The
 * passwords are never written to the console and never put in the URL.
 *
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import { changeMyPassword, getMyAccount, listMySessions, patchMyAccount, revokeMySession } from '@/api/account';
import type { MyAccount, MyAccountPatch, SessionSummary } from '@/api/types';

const SESSION_ID = '3f2b8c1d-9e4a-4b7c-8d6e-0a1b2c3d4e5f';
const OTHER_SESSION_ID = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';

const CURRENT_PASSWORD = 'old-Secret-pass-2025';
const NEW_PASSWORD = 'brand new Passphrase 2026!';

const fetchMock = vi.fn<typeof fetch>();

const ACCOUNT: MyAccount = {
  email: 'alice@example.ch',
  name: 'Alice Muster',
  ui_language: 'de',
  response_language: null,
  timezone: 'Europe/Zurich',
  personal_instructions: '',
};

const SESSIONS: SessionSummary[] = [
  {
    id: SESSION_ID,
    created_at: '2026-10-01T08:00:00Z',
    last_seen_at: '2026-10-03T07:45:00Z',
    expires_at: '2026-10-31T08:00:00Z',
    ip: '198.51.100.7',
    user_agent: 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
    current: true,
  },
  {
    id: OTHER_SESSION_ID,
    created_at: '2026-09-20T18:00:00Z',
    last_seen_at: '2026-09-28T19:10:00Z',
    expires_at: '2026-10-20T18:00:00Z',
    ip: null,
    user_agent: null,
    current: false,
  },
];

const STATUS_TEXT: Record<number, string> = {
  200: 'OK',
  403: 'Forbidden',
  404: 'Not Found',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: STATUS_TEXT[status] ?? '',
    headers: { 'Content-Type': 'application/json' },
  });
}

function emptyResponse(status: number): Response {
  return new Response(null, { status });
}

/** The (url, method, body) of the only fetch call made. */
function onlyRequest(): { url: unknown; method: unknown; body: unknown } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0];
  return { url, method: init?.method ?? 'GET', body: init?.body };
}

/** The parsed JSON body of the first fetch call (`undefined` when there is none). */
function sentJson(): unknown {
  const body = fetchMock.mock.calls[0]?.[1]?.body;
  return body === undefined || body === null ? undefined : (JSON.parse(String(body)) as unknown);
}

/** The error a call throws (synchronously or as a rejection); fails when it doesn't throw. */
async function thrownBy(fn: () => unknown): Promise<unknown> {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected the call to throw');
}

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

// --- Request formation and resolved values (every function) ---------------

interface RequestCase {
  name: string;
  call: () => Promise<unknown>;
  response: () => Response;
  url: string;
  method: string;
  json: unknown;
  resolves: unknown;
}

const REQUEST_CASES: readonly RequestCase[] = [
  {
    name: 'getMyAccount',
    call: () => getMyAccount(),
    response: () => jsonResponse(200, ACCOUNT),
    url: '/api/me',
    method: 'GET',
    json: undefined,
    resolves: ACCOUNT,
  },
  {
    name: 'patchMyAccount',
    call: () => patchMyAccount({ name: 'Alice Keller' }),
    response: () => jsonResponse(200, { ...ACCOUNT, name: 'Alice Keller' }),
    url: '/api/me',
    method: 'PATCH',
    json: { name: 'Alice Keller' },
    resolves: { ...ACCOUNT, name: 'Alice Keller' },
  },
  {
    name: 'changeMyPassword',
    call: () => changeMyPassword(CURRENT_PASSWORD, NEW_PASSWORD),
    response: () => emptyResponse(204),
    url: '/api/me/password',
    method: 'POST',
    json: { current_password: CURRENT_PASSWORD, new_password: NEW_PASSWORD },
    resolves: undefined,
  },
  {
    name: 'listMySessions',
    call: () => listMySessions(),
    response: () => jsonResponse(200, { sessions: SESSIONS }),
    url: '/api/me/sessions',
    method: 'GET',
    json: undefined,
    resolves: SESSIONS,
  },
  {
    name: 'revokeMySession',
    call: () => revokeMySession(SESSION_ID),
    response: () => emptyResponse(204),
    url: `/api/me/sessions/${SESSION_ID}`,
    method: 'DELETE',
    json: undefined,
    resolves: undefined,
  },
];

describe('account API requests', () => {
  it.each(REQUEST_CASES)('$name sends $method $url with exactly the expected body', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    await c.call();

    const sent = onlyRequest();
    expect({ url: sent.url, method: sent.method, json: sentJson() }).toStrictEqual({
      url: c.url,
      method: c.method,
      json: c.json,
    });
  });

  it.each(REQUEST_CASES)('$name resolves the expected value', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    const result = await c.call();

    expect({ calls: fetchMock.mock.calls.length, result }).toStrictEqual({ calls: 1, result: c.resolves });
  });

  it.each(REQUEST_CASES)(
    "$name sends the session cookie (credentials: 'same-origin') and no Authorization header",
    async (c) => {
      localStorage.setItem('admino_auth_token', 'legacy-bearer-token');
      fetchMock.mockResolvedValueOnce(c.response());

      await c.call();

      const init = fetchMock.mock.calls[0]?.[1];
      expect({
        credentials: init?.credentials,
        authorization: new Headers(init?.headers).has('authorization'),
      }).toEqual({ credentials: 'same-origin', authorization: false });
    },
  );
});

describe('patchMyAccount body', () => {
  it.each([
    ['name only', { name: 'Alice Keller' }],
    ['ui_language only', { ui_language: 'fr' as const }],
    ['response_language set', { response_language: 'it' as const }],
    ['response_language back to the org default (null)', { response_language: null }],
    ['timezone only', { timezone: 'America/Argentina/Buenos_Aires' }],
    ['personal instructions with surrounding whitespace', { personal_instructions: '  Sign off with "Grüsse",\n' }],
    ['personal instructions cleared', { personal_instructions: '' }],
    [
      'several fields',
      { name: 'Alice Keller', response_language: null, timezone: 'Asia/Tokyo', personal_instructions: 'Be brief.' },
    ],
  ] as Array<[string, MyAccountPatch]>)('sends exactly the given patch (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ACCOUNT));

    await patchMyAccount(patch);

    const body = fetchMock.mock.calls[0]?.[1]?.body;
    expect({ body, parsed: JSON.parse(String(body)) as unknown }).toStrictEqual({
      body: JSON.stringify(patch),
      parsed: patch,
    });
  });

  it('sends response_language: null as an explicit null (org default), not as a missing key', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ACCOUNT));

    await patchMyAccount({ response_language: null });

    const parsed = sentJson() as Record<string, unknown>;
    expect({ hasKey: Object.hasOwn(parsed, 'response_language'), value: parsed.response_language }).toEqual({
      hasKey: true,
      value: null,
    });
  });

  it('resolves the updated account from the response', async () => {
    const updated: MyAccount = { ...ACCOUNT, response_language: 'fr', timezone: 'Europe/Paris' };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, updated));

    const result = await patchMyAccount({ response_language: 'fr', timezone: 'Europe/Paris' });

    expect(result).toEqual(updated);
  });
});

describe('changeMyPassword body', () => {
  it('sends exactly {"current_password", "new_password"} and nothing else', async () => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await changeMyPassword('current pass "quoted" ü', 'next pass with spaces and 😀');

    expect(sentJson()).toStrictEqual({
      current_password: 'current pass "quoted" ü',
      new_password: 'next pass with spaces and 😀',
    });
  });

  it('never puts a password into the URL', async () => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await changeMyPassword(CURRENT_PASSWORD, NEW_PASSWORD);

    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect({ current: url.includes(CURRENT_PASSWORD), next: url.includes(NEW_PASSWORD) }).toEqual({
      current: false,
      next: false,
    });
  });

  it.each([
    ['succeeds', () => emptyResponse(204)],
    ['is refused (403)', () => jsonResponse(403, { detail: 'Re-authentication failed.' })],
    ['fails the policy (422)', () => jsonResponse(422, { detail: 'Password is too short.', reason: 'too_short' })],
  ] as Array<[string, () => Response]>)('never writes a password to the console when the change %s', async (_label, response) => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
    fetchMock.mockResolvedValueOnce(response());

    await changeMyPassword(CURRENT_PASSWORD, NEW_PASSWORD).catch(() => undefined);

    const logged = spies.flatMap((spy) => spy.mock.calls.map((args) => args.map((arg) => String(arg)).join(' ')));
    expect(logged.filter((line) => line.includes(CURRENT_PASSWORD) || line.includes(NEW_PASSWORD))).toEqual([]);
  });
});

describe('listMySessions', () => {
  it('resolves the sessions array, not the wrapper object', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { sessions: SESSIONS }));

    const result = await listMySessions();

    expect({ isArray: Array.isArray(result), result }).toStrictEqual({ isArray: true, result: SESSIONS });
  });

  it('resolves an empty list as []', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { sessions: [] }));

    expect(await listMySessions()).toStrictEqual([]);
  });
});

// --- Errors ------------------------------------------------------------------

describe('account API errors', () => {
  const ERROR_CASES: ReadonlyArray<{
    name: string;
    call: () => Promise<unknown>;
    status: number;
    reason: string | undefined;
  }> = [
    { name: 'getMyAccount (gone)', call: () => getMyAccount(), status: 404, reason: undefined },
    { name: 'getMyAccount (rate limited)', call: () => getMyAccount(), status: 429, reason: undefined },
    { name: 'patchMyAccount (invalid)', call: () => patchMyAccount({ timezone: 'Mars/Olympus' }), status: 422, reason: undefined },
    { name: 'patchMyAccount (rate limited)', call: () => patchMyAccount({ name: 'Alice' }), status: 429, reason: undefined },
    { name: 'patchMyAccount (server)', call: () => patchMyAccount({ name: 'Alice' }), status: 500, reason: undefined },
    { name: 'changeMyPassword (wrong current)', call: () => changeMyPassword('wrong', NEW_PASSWORD), status: 403, reason: undefined },
    { name: 'changeMyPassword (too short)', call: () => changeMyPassword(CURRENT_PASSWORD, 'short'), status: 422, reason: 'too_short' },
    { name: 'changeMyPassword (too long)', call: () => changeMyPassword(CURRENT_PASSWORD, 'x'.repeat(200)), status: 422, reason: 'too_long' },
    { name: 'changeMyPassword (common)', call: () => changeMyPassword(CURRENT_PASSWORD, 'password1234'), status: 422, reason: 'common' },
    { name: 'changeMyPassword (equals email)', call: () => changeMyPassword(CURRENT_PASSWORD, 'alice@example.ch'), status: 422, reason: 'equals_email' },
    { name: 'changeMyPassword (rate limited)', call: () => changeMyPassword(CURRENT_PASSWORD, NEW_PASSWORD), status: 429, reason: undefined },
    { name: 'listMySessions (rate limited)', call: () => listMySessions(), status: 429, reason: undefined },
    { name: 'revokeMySession (gone)', call: () => revokeMySession(SESSION_ID), status: 404, reason: undefined },
  ];

  it.each(ERROR_CASES)('$name rejects $status ($reason) as an ApiError carrying status and reason', async (c) => {
    const detail = `Backend detail for ${c.name}.`;
    const body: Record<string, string> = { detail };
    if (c.reason !== undefined) body.reason = c.reason;
    fetchMock.mockResolvedValueOnce(jsonResponse(c.status, body));

    const error = await thrownBy(c.call);

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      reason: (error as ApiError).reason,
      message: (error as ApiError).message,
      calls: fetchMock.mock.calls.length,
    }).toEqual({ status: c.status, reason: c.reason, message: detail, calls: 1 });
  });

  it('a network failure rejects (never resolves a fake success)', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const error = await thrownBy(() => changeMyPassword(CURRENT_PASSWORD, NEW_PASSWORD));

    expect(error).toBeInstanceOf(TypeError);
  });
});

// --- Path-injection guard ------------------------------------------------------

describe('revokeMySession id guard', () => {
  const BAD_IDS: ReadonlyArray<[string, string]> = [
    ['parent path', '../x'],
    ['empty', ''],
    ['short word', 'abc'],
    ['UUID with a trailing path segment', `${SESSION_ID}/x`],
    ['encoded dots', '%2e%2e'],
    ['UUID with a trailing newline', `${SESSION_ID}\n`],
    ['UUID with a leading space', ` ${SESSION_ID}`],
    ['UUID behind a parent path', `../${SESSION_ID}`],
    ['UUID with a query', `${SESSION_ID}?x=1`],
    ['UUID with a fragment', `${SESSION_ID}#x`],
    ['non-hex character', '3f2b8c1d-9e4a-4b7c-8d6e-0a1b2c3d4e5g'],
    ['UUID without dashes', '3f2b8c1d9e4a4b7c8d6e0a1b2c3d4e5f'],
  ];

  it.each(BAD_IDS)('refuses a %s id with Error("Invalid session id") and makes no request', async (_label, id) => {
    fetchMock.mockResolvedValue(emptyResponse(204));

    const error = await thrownBy(() => revokeMySession(id));

    expect({
      isError: error instanceof Error,
      isApiError: error instanceof ApiError,
      message: (error as Error).message,
      requests: fetchMock.mock.calls.length,
    }).toEqual({ isError: true, isApiError: false, message: 'Invalid session id', requests: 0 });
  });

  it('accepts an upper-case UUID (the id check is case-insensitive)', async () => {
    const upper = SESSION_ID.toUpperCase();
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await revokeMySession(upper);

    expect(onlyRequest()).toEqual({ url: `/api/me/sessions/${upper}`, method: 'DELETE', body: undefined });
  });

  it('puts a valid id into the URL as exactly one path segment', async () => {
    fetchMock.mockResolvedValueOnce(emptyResponse(204));

    await revokeMySession(OTHER_SESSION_ID);

    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url.split('/')).toEqual(['', 'api', 'me', 'sessions', OTHER_SESSION_ID]);
  });
});
