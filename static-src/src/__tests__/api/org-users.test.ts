/**
 * Org users and invitations API client tests (issue #165: Organization
 * console, users and invitations UI; the backend routes come from #153
 * (invitations) and #164 (org users)).
 *
 * `@/api/org-users` wraps, through `fetchJson` (so every call carries the
 * session cookie, `credentials: 'same-origin'`, and a non-2xx answer throws
 * an `ApiError` with `.status` and `.reason`):
 * - `listOrgUsers()` -> `GET /api/org/users` (users + the org's seat usage),
 * - `updateOrgUser(id, patch)` -> `PATCH /api/org/users/{id}`, body exactly
 *   the given patch (only the given fields),
 * - `deactivateOrgUser(id)` / `reactivateOrgUser(id)` ->
 *   `POST /api/org/users/{id}/deactivate|reactivate`, no body,
 * - `deleteOrgUser(id)` -> `DELETE /api/org/users/{id}` (204),
 * - `resetOrgUserPassword(id)` -> `POST /api/org/users/{id}/password-reset`
 *   (202), `forceLogoutOrgUser(id)` -> `POST /api/org/users/{id}/logout` (204),
 * - `listInvitations()` -> `GET /api/org/invitations`,
 * - `createInvitation(email, role)` -> `POST /api/org/invitations`, body
 *   exactly `{"email": email, "role": role}` (201),
 * - `revokeInvitation(id)` -> `DELETE /api/org/invitations/{id}` (204),
 * - `resendInvitation(id)` -> `POST /api/org/invitations/{id}/resend`.
 * 202/204 answers resolve `undefined`. A 409 such as
 * `{"detail", "reason": "last_admin"}` surfaces as an `ApiError` with status
 * 409 and that reason (also `email_taken`, `seat_limit`, `invalid_status`).
 *
 * Path-injection guard: every `id` must be a UUID
 * (`/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`);
 * anything else throws a plain `Error('Invalid id')` (not an `ApiError`)
 * and makes NO request, for every id-taking function.
 *
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import {
  createInvitation,
  deactivateOrgUser,
  deleteOrgUser,
  forceLogoutOrgUser,
  listInvitations,
  listOrgUsers,
  reactivateOrgUser,
  resendInvitation,
  resetOrgUserPassword,
  revokeInvitation,
  updateOrgUser,
} from '@/api/org-users';
import type {
  OrgInvitation,
  OrgInvitationListResponse,
  OrgUser,
  OrgUserListResponse,
} from '@/api/types';

const USER_ID = '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90';
const OTHER_USER_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';
const INVITATION_ID = '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f';

const fetchMock = vi.fn<typeof fetch>();

const ALICE: OrgUser = {
  id: USER_ID,
  name: 'Alice Muster',
  email: 'alice@example.ch',
  role: 'editor',
  status: 'active',
  created_at: '2026-09-01T08:00:00Z',
  last_login_at: '2026-10-01T07:30:00Z',
};

const ALICE_DEACTIVATED: OrgUser = { ...ALICE, status: 'deactivated' };

const LIST: OrgUserListResponse = {
  users: [
    ALICE,
    {
      id: OTHER_USER_ID,
      name: null,
      email: 'bruno@example.ch',
      role: 'org_admin',
      status: 'active',
      created_at: '2026-08-15T10:00:00Z',
      last_login_at: null,
    },
  ],
  seats: { used: 3, limit: 10 },
};

const INVITATION: OrgInvitation = {
  id: INVITATION_ID,
  email: 'carla@example.ch',
  role: 'editor',
  sent_at: '2026-10-02T09:00:00Z',
  expires_at: '2026-10-09T09:00:00Z',
  expired: false,
};

const RESENT: OrgInvitation = {
  ...INVITATION,
  sent_at: '2026-10-03T09:00:00Z',
  expires_at: '2026-10-10T09:00:00Z',
};

const INVITATIONS: OrgInvitationListResponse = { invitations: [INVITATION] };

const STATUS_TEXT: Record<number, string> = {
  200: 'OK',
  201: 'Created',
  403: 'Forbidden',
  404: 'Not Found',
  409: 'Conflict',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
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
  body: string | undefined;
  resolves: unknown;
}

const REQUEST_CASES: readonly RequestCase[] = [
  {
    name: 'listOrgUsers',
    call: () => listOrgUsers(),
    response: () => jsonResponse(200, LIST),
    url: '/api/org/users',
    method: 'GET',
    body: undefined,
    resolves: LIST,
  },
  {
    name: 'updateOrgUser (role only)',
    call: () => updateOrgUser(USER_ID, { role: 'org_admin' }),
    response: () => jsonResponse(200, { ...ALICE, role: 'org_admin' }),
    url: `/api/org/users/${USER_ID}`,
    method: 'PATCH',
    body: JSON.stringify({ role: 'org_admin' }),
    resolves: { ...ALICE, role: 'org_admin' },
  },
  {
    name: 'deactivateOrgUser',
    call: () => deactivateOrgUser(USER_ID),
    response: () => jsonResponse(200, ALICE_DEACTIVATED),
    url: `/api/org/users/${USER_ID}/deactivate`,
    method: 'POST',
    body: undefined,
    resolves: ALICE_DEACTIVATED,
  },
  {
    name: 'reactivateOrgUser',
    call: () => reactivateOrgUser(USER_ID),
    response: () => jsonResponse(200, ALICE),
    url: `/api/org/users/${USER_ID}/reactivate`,
    method: 'POST',
    body: undefined,
    resolves: ALICE,
  },
  {
    name: 'deleteOrgUser',
    call: () => deleteOrgUser(USER_ID),
    response: () => emptyResponse(204),
    url: `/api/org/users/${USER_ID}`,
    method: 'DELETE',
    body: undefined,
    resolves: undefined,
  },
  {
    name: 'resetOrgUserPassword',
    call: () => resetOrgUserPassword(USER_ID),
    response: () => emptyResponse(202),
    url: `/api/org/users/${USER_ID}/password-reset`,
    method: 'POST',
    body: undefined,
    resolves: undefined,
  },
  {
    name: 'forceLogoutOrgUser',
    call: () => forceLogoutOrgUser(USER_ID),
    response: () => emptyResponse(204),
    url: `/api/org/users/${USER_ID}/logout`,
    method: 'POST',
    body: undefined,
    resolves: undefined,
  },
  {
    name: 'listInvitations',
    call: () => listInvitations(),
    response: () => jsonResponse(200, INVITATIONS),
    url: '/api/org/invitations',
    method: 'GET',
    body: undefined,
    resolves: INVITATIONS,
  },
  {
    name: 'createInvitation',
    call: () => createInvitation('carla@example.ch', 'editor'),
    response: () => jsonResponse(201, INVITATION),
    url: '/api/org/invitations',
    method: 'POST',
    body: JSON.stringify({ email: 'carla@example.ch', role: 'editor' }),
    resolves: INVITATION,
  },
  {
    name: 'revokeInvitation',
    call: () => revokeInvitation(INVITATION_ID),
    response: () => emptyResponse(204),
    url: `/api/org/invitations/${INVITATION_ID}`,
    method: 'DELETE',
    body: undefined,
    resolves: undefined,
  },
  {
    name: 'resendInvitation',
    call: () => resendInvitation(INVITATION_ID),
    response: () => jsonResponse(200, RESENT),
    url: `/api/org/invitations/${INVITATION_ID}/resend`,
    method: 'POST',
    body: undefined,
    resolves: RESENT,
  },
];

describe('org-users API requests', () => {
  it.each(REQUEST_CASES)('$name sends $method $url with the expected body', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    await c.call();

    const sent = onlyRequest();
    // createInvitation's body is checked key-order-free below; here the exact string.
    expect(sent).toEqual({ url: c.url, method: c.method, body: c.body });
  });

  it.each(REQUEST_CASES)('$name resolves the expected value', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    const result = await c.call();

    expect({ calls: fetchMock.mock.calls.length, result }).toEqual({ calls: 1, result: c.resolves });
  });

  it.each(REQUEST_CASES)('$name sends the session cookie (credentials same-origin)', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    await c.call();

    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('same-origin');
  });
});

describe('updateOrgUser body', () => {
  it.each([
    ['name only', { name: 'Alice Keller' }],
    ['email only', { email: 'alice.keller@example.ch' }],
    ['name and email', { name: 'Alice Keller', email: 'alice.keller@example.ch' }],
    ['role only', { role: 'editor' as const }],
  ])('sends exactly the given patch (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ALICE));

    await updateOrgUser(USER_ID, patch);

    const body = fetchMock.mock.calls[0]?.[1]?.body;
    expect({ body, parsed: JSON.parse(String(body)) as unknown }).toStrictEqual({
      body: JSON.stringify(patch),
      parsed: patch,
    });
  });

  it('resolves the updated user from the response', async () => {
    const updated: OrgUser = { ...ALICE, name: 'Alice Keller', email: 'alice.keller@example.ch' };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, updated));

    const result = await updateOrgUser(USER_ID, { name: 'Alice Keller', email: 'alice.keller@example.ch' });

    expect(result).toEqual(updated);
  });
});

describe('createInvitation body', () => {
  it('sends exactly {"email", "role"} and nothing else', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, INVITATION));

    await createInvitation('carla@example.ch', 'org_admin');

    const body = fetchMock.mock.calls[0]?.[1]?.body;
    expect(JSON.parse(String(body))).toStrictEqual({ email: 'carla@example.ch', role: 'org_admin' });
  });

  it('JSON-encodes an email with quotes and non-ASCII characters verbatim', async () => {
    const tricky = 'o"brien.zoë@exämple.ch';
    fetchMock.mockResolvedValueOnce(jsonResponse(201, { ...INVITATION, email: tricky }));

    await createInvitation(tricky, 'editor');

    const body = fetchMock.mock.calls[0]?.[1]?.body;
    expect({ url: fetchMock.mock.calls[0]?.[0], parsed: JSON.parse(String(body)) as unknown }).toStrictEqual({
      url: '/api/org/invitations',
      parsed: { email: tricky, role: 'editor' },
    });
  });

  it('never puts the email into the URL', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, INVITATION));

    await createInvitation('carla@example.ch', 'editor');

    expect(String(fetchMock.mock.calls[0]?.[0]).includes('carla')).toBe(false);
  });
});

describe('ids', () => {
  it('accepts an upper-case UUID (the id check is case-insensitive)', async () => {
    const upper = USER_ID.toUpperCase();
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ALICE_DEACTIVATED));

    await deactivateOrgUser(upper);

    expect(onlyRequest()).toEqual({ url: `/api/org/users/${upper}/deactivate`, method: 'POST', body: undefined });
  });
});

// --- Errors ------------------------------------------------------------------

describe('org-users API errors', () => {
  const ERROR_CASES: ReadonlyArray<{
    name: string;
    call: () => Promise<unknown>;
    status: number;
    reason: string | undefined;
  }> = [
    { name: 'updateOrgUser (role)', call: () => updateOrgUser(USER_ID, { role: 'editor' }), status: 409, reason: 'last_admin' },
    { name: 'deactivateOrgUser', call: () => deactivateOrgUser(USER_ID), status: 409, reason: 'last_admin' },
    { name: 'deleteOrgUser', call: () => deleteOrgUser(USER_ID), status: 409, reason: 'last_admin' },
    { name: 'updateOrgUser (email)', call: () => updateOrgUser(USER_ID, { email: 'b@example.ch' }), status: 409, reason: 'email_taken' },
    { name: 'createInvitation (taken)', call: () => createInvitation('b@example.ch', 'editor'), status: 409, reason: 'email_taken' },
    { name: 'createInvitation (full)', call: () => createInvitation('d@example.ch', 'editor'), status: 409, reason: 'seat_limit' },
    { name: 'reactivateOrgUser', call: () => reactivateOrgUser(USER_ID), status: 409, reason: 'seat_limit' },
    { name: 'resetOrgUserPassword', call: () => resetOrgUserPassword(USER_ID), status: 409, reason: 'invalid_status' },
    { name: 'deactivateOrgUser (already)', call: () => deactivateOrgUser(USER_ID), status: 409, reason: 'invalid_status' },
    { name: 'forceLogoutOrgUser (other org)', call: () => forceLogoutOrgUser(USER_ID), status: 404, reason: undefined },
    { name: 'revokeInvitation (gone)', call: () => revokeInvitation(INVITATION_ID), status: 404, reason: undefined },
    { name: 'resendInvitation (gone)', call: () => resendInvitation(INVITATION_ID), status: 404, reason: undefined },
    { name: 'listOrgUsers (not an Org Admin)', call: () => listOrgUsers(), status: 403, reason: undefined },
    { name: 'listInvitations (not an Org Admin)', call: () => listInvitations(), status: 403, reason: undefined },
    { name: 'createInvitation (rate limited)', call: () => createInvitation('e@example.ch', 'editor'), status: 429, reason: undefined },
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

    const error = await thrownBy(() => deactivateOrgUser(USER_ID));

    expect(error).toBeInstanceOf(TypeError);
  });
});

// --- Path-injection guard ------------------------------------------------------

describe('org-users API id guard', () => {
  const ID_FUNCTIONS: ReadonlyArray<[string, (id: string) => Promise<unknown>]> = [
    ['updateOrgUser', (id) => updateOrgUser(id, { name: 'Alice Keller' })],
    ['deactivateOrgUser', (id) => deactivateOrgUser(id)],
    ['reactivateOrgUser', (id) => reactivateOrgUser(id)],
    ['deleteOrgUser', (id) => deleteOrgUser(id)],
    ['resetOrgUserPassword', (id) => resetOrgUserPassword(id)],
    ['forceLogoutOrgUser', (id) => forceLogoutOrgUser(id)],
    ['revokeInvitation', (id) => revokeInvitation(id)],
    ['resendInvitation', (id) => resendInvitation(id)],
  ];

  const BAD_IDS: ReadonlyArray<[string, string]> = [
    ['parent path', '../settings'],
    ['empty', ''],
    ['short word', 'abc'],
    ['UUID with a trailing path segment', `${USER_ID}/x`],
    ['encoded dots', '%2e%2e'],
    ['UUID with a trailing newline', `${USER_ID}\n`],
    ['UUID with a leading space', ` ${USER_ID}`],
    ['UUID behind a parent path', `../${USER_ID}`],
    ['UUID with a query', `${USER_ID}?x=1`],
    ['non-hex character', '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a9g'],
    ['UUID without dashes', '0b9f6c1e3a524c1d9a8e5f2d7c3b1a90'],
  ];

  describe.each(ID_FUNCTIONS)('%s', (_name, call) => {
    it.each(BAD_IDS)('refuses a %s id with Error("Invalid id") and makes no request', async (_label, id) => {
      fetchMock.mockResolvedValue(jsonResponse(200, ALICE));

      const error = await thrownBy(() => call(id));

      expect({
        isError: error instanceof Error,
        isApiError: error instanceof ApiError,
        message: (error as Error).message,
        requests: fetchMock.mock.calls.length,
      }).toEqual({ isError: true, isApiError: false, message: 'Invalid id', requests: 0 });
    });
  });
});
