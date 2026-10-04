/**
 * Platform console API client tests (issue #168: Platform console UI for the
 * Super Admin; the backend routes come from #154 (organizations), #167 (users
 * and metadata) and #160 + #242 (platform defaults and the model policy)).
 *
 * `@/api/platform` wraps, through `fetchJson` (so every call carries the
 * session cookie, `credentials: 'same-origin'`, and a non-2xx answer throws
 * an `ApiError` with `.status` and `.reason`; 202/204 resolve `undefined`):
 * - `listPlatformOrgs()` -> `GET /api/platform/orgs`,
 * - `createPlatformOrg(body)` -> `POST /api/platform/orgs`, body exactly `body`,
 * - `updatePlatformOrgLimits(orgId, patch)` ->
 *   `PATCH /api/platform/orgs/{orgId}/limits`, body exactly `patch`,
 * - `deactivatePlatformOrg` / `reactivatePlatformOrg` /
 *   `schedulePlatformOrgDeletion(orgId)` ->
 *   `POST /api/platform/orgs/{orgId}/deactivate|reactivate|deletion`, no body,
 * - `cancelPlatformOrgDeletion(orgId)` -> `DELETE /api/platform/orgs/{orgId}/deletion`,
 * - `setPlatformOrgResidency(orgId, enabled)` ->
 *   `PATCH /api/platform/orgs/{orgId}/residency`, body exactly `{"enabled": enabled}`,
 * - `listPlatformOrgUsers(orgId)` / `getPlatformOrgMetadata(orgId)` ->
 *   `GET /api/platform/orgs/{orgId}/users|metadata`,
 * - `deactivatePlatformUser` / `reactivatePlatformUser(orgId, userId)` ->
 *   `POST /api/platform/orgs/{orgId}/users/{userId}/deactivate|reactivate`, no body,
 * - `resetPlatformUserPassword(orgId, userId)` ->
 *   `POST .../users/{userId}/password-reset` (202, resolves `undefined`),
 * - `reinvitePlatformUser(orgId, userId, email?)` ->
 *   `POST .../users/{userId}/invitation`; no email -> body exactly `{}`
 *   (resend with a new link), an email -> body exactly `{"email": email}`
 *   (replace the invited account). An empty string is an email the caller
 *   gave, so it is sent as is (the backend refuses it rather than taking it
 *   as "no email", docs/configuration.md "Users and metadata"),
 * - `getPlatformSettings()` -> `GET /api/platform/settings`,
 * - `patchPlatformSettings(patch)` -> `PATCH /api/platform/settings`, body
 *   exactly `patch` (including `confirm_residency_orgs` when given).
 *
 * A 409 such as `{"detail", "reason": "residency_confirmation"}` surfaces as
 * an `ApiError` with status 409 and that reason code (also `email_taken`,
 * `last_admin`, `has_active_admin`, `seat_limit`, `invalid_status`); the
 * reason is the code, never the backend's detail text.
 *
 * Path-injection guard: every org id and user id must be a UUID
 * (`/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`);
 * anything else (`'../x'`, `'a/b'`, `''`, a UUID with a suffix, ...) throws a
 * plain `Error('Invalid id')` (not an `ApiError`) and makes NO request.
 *
 * Operator blindness (#139 §5): every request any function makes goes to a
 * path under `/api/platform/`, the Super Admin's metadata-only routes.
 *
 * `fetch` is stubbed; nothing touches the network. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import {
  cancelPlatformOrgDeletion,
  createPlatformOrg,
  deactivatePlatformOrg,
  deactivatePlatformUser,
  getPlatformOrgMetadata,
  getPlatformSettings,
  listPlatformOrgs,
  listPlatformOrgUsers,
  patchPlatformSettings,
  reactivatePlatformOrg,
  reactivatePlatformUser,
  reinvitePlatformUser,
  resetPlatformUserPassword,
  schedulePlatformOrgDeletion,
  setPlatformOrgResidency,
  updatePlatformOrgLimits,
} from '@/api/platform';
import type {
  OrgInvitation,
  PlatformOrg,
  PlatformOrgCreateRequest,
  PlatformOrgCreateResponse,
  PlatformOrgLimitsPatch,
  PlatformOrgListResponse,
  PlatformOrgMetadata,
  PlatformSettings,
  PlatformSettingsPatch,
  PlatformUser,
  PlatformUserListResponse,
} from '@/api/types';

const ORG_ID = '3c5e7a90-1b2d-4f6e-8a0c-9d1e2f3a4b5c';
const OTHER_ORG_ID = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const USER_ID = '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90';
const ADMIN_ID = '7d3e2f10-6b4a-4e8c-8f1d-2a9b0c5e6d71';
const INVITATION_ID = '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f';

const GIB = 1024 ** 3;

const fetchMock = vi.fn<typeof fetch>();

const ORG: PlatformOrg = {
  id: ORG_ID,
  name: 'Muster AG',
  status: 'active',
  seats: 10,
  monthly_budget_chf: '100.00',
  storage_quota: 10 * GIB,
  data_residency: true,
  deletion_requested_at: null,
  purge_after: null,
  created_at: '2026-09-01T08:00:00Z',
  updated_at: '2026-09-01T08:00:00Z',
};

const OTHER_ORG: PlatformOrg = {
  ...ORG,
  id: OTHER_ORG_ID,
  name: 'Beispiel GmbH',
  status: 'deactivated',
  seats: 3,
  data_residency: false,
};

const ORG_LIST: PlatformOrgListResponse = { organizations: [ORG, OTHER_ORG] };

const ORG_DEACTIVATED: PlatformOrg = { ...ORG, status: 'deactivated', updated_at: '2026-10-01T09:00:00Z' };

const ORG_PENDING: PlatformOrg = {
  ...ORG,
  status: 'pending_deletion',
  deletion_requested_at: '2026-10-01T09:00:00Z',
  purge_after: '2026-10-31T09:00:00Z',
  updated_at: '2026-10-01T09:00:00Z',
};

const ORG_RESIDENCY_OFF: PlatformOrg = { ...ORG, data_residency: false, updated_at: '2026-10-01T09:00:00Z' };

const ORG_LIMITS: PlatformOrg = {
  ...ORG,
  seats: 25,
  monthly_budget_chf: '250.50',
  storage_quota: 20 * GIB,
  updated_at: '2026-10-01T09:00:00Z',
};

const CREATE_BODY: PlatformOrgCreateRequest = {
  name: 'Neue Firma AG',
  primary_admin_email: 'admin@neue-firma.ch',
  seats: 10,
  monthly_budget_chf: '100.00',
  storage_quota: 10 * GIB,
};

const INVITATION: OrgInvitation = {
  id: INVITATION_ID,
  email: 'admin@neue-firma.ch',
  role: 'org_admin',
  sent_at: '2026-10-02T09:00:00Z',
  expires_at: '2026-10-05T09:00:00Z',
  expired: false,
};

const CREATED: PlatformOrgCreateResponse = {
  organization: { ...ORG, id: OTHER_ORG_ID, name: 'Neue Firma AG' },
  invitation: INVITATION,
};

const USER: PlatformUser = {
  id: USER_ID,
  name: 'Alice Muster',
  email: 'alice@muster.ch',
  role: 'editor',
  status: 'active',
  created_at: '2026-09-01T08:00:00Z',
  last_login_at: '2026-10-01T07:30:00Z',
};

const USER_DEACTIVATED: PlatformUser = { ...USER, status: 'deactivated' };

const INVITED_ADMIN: PlatformUser = {
  id: ADMIN_ID,
  name: null,
  email: 'chef@muster.ch',
  role: 'org_admin',
  status: 'invited',
  created_at: '2026-09-01T08:00:00Z',
  last_login_at: null,
};

const USER_LIST: PlatformUserListResponse = { users: [INVITED_ADMIN, USER] };

const METADATA: PlatformOrgMetadata = {
  seats: { used: 3, limit: 10 },
  storage_used_bytes: 0,
  chat_count: 0,
  file_count: 0,
};

const REINVITED: OrgInvitation = {
  ...INVITATION,
  id: ADMIN_ID,
  email: 'chef@muster.ch',
  sent_at: '2026-10-03T09:00:00Z',
  expires_at: '2026-10-06T09:00:00Z',
};

const SETTINGS: PlatformSettings = {
  llm: {
    provider: 'infomaniak',
    anthropic_model: 'claude-sonnet-4-5',
    openai_model: 'gpt-4o',
    infomaniak_model: 'qwen3',
    vllm_model: 'Qwen/Qwen2.5-0.5B-Instruct',
    infomaniak_available_models: ['qwen3', 'mistral3'],
    vllm_available_models: ['Qwen/Qwen2.5-0.5B-Instruct'],
    max_input_tokens: 100000,
    image_input: false,
    max_retries: 2,
    residency_orgs: 3,
    anthropic_key_configured: false,
    openai_key_configured: true,
    infomaniak_token_configured: true,
  },
  limits: {
    max_tool_calls_per_message: 10,
    max_pending_confirmations: 5,
    confirmation_timeout_s: 300,
    max_message_length: 10000,
    max_context_messages: 50,
  },
  files: { max_file_size_mb: 25, max_files_per_message: 5, max_pages_per_file: 100, render_dpi: 150 },
  retention: { trash_min_days: 7, trash_max_days: 30, audit_months: 12, org_deletion_grace_days: 30 },
  security: {
    rate_limit_per_minute: 60,
    lockout_after_failures: 5,
    lockout_window_minutes: 15,
    lockout_minutes: 15,
    session_idle_timeout_minutes: 60,
    session_max_lifetime_hours: 24,
  },
};

const SETTINGS_ANTHROPIC: PlatformSettings = {
  ...SETTINGS,
  llm: { ...SETTINGS.llm, provider: 'anthropic' },
};

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

/** A request body as sent: `undefined` for no body (absent or null), else the parsed JSON. */
function parsedBody(body: unknown): unknown {
  return body === undefined || body === null ? undefined : (JSON.parse(String(body)) as unknown);
}

/** The (url, method, parsed body) of the only fetch call made. */
function onlyRequest(): { url: unknown; method: unknown; body: unknown } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0];
  return { url, method: init?.method ?? 'GET', body: parsedBody(init?.body) };
}

/** The raw body string of the only fetch call made. */
function onlyRawBody(): unknown {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  return fetchMock.mock.calls[0]?.[1]?.body;
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
  /** The parsed JSON body, or `undefined` for no body. */
  body: unknown;
  resolves: unknown;
}

const ORGS = `/api/platform/orgs`;

const REQUEST_CASES: readonly RequestCase[] = [
  {
    name: 'listPlatformOrgs',
    call: () => listPlatformOrgs(),
    response: () => jsonResponse(200, ORG_LIST),
    url: ORGS,
    method: 'GET',
    body: undefined,
    resolves: ORG_LIST,
  },
  {
    name: 'createPlatformOrg',
    call: () => createPlatformOrg(CREATE_BODY),
    response: () => jsonResponse(201, CREATED),
    url: ORGS,
    method: 'POST',
    body: CREATE_BODY,
    resolves: CREATED,
  },
  {
    name: 'updatePlatformOrgLimits',
    call: () => updatePlatformOrgLimits(ORG_ID, { seats: 25, monthly_budget_chf: '250.50', storage_quota: 20 * GIB }),
    response: () => jsonResponse(200, ORG_LIMITS),
    url: `${ORGS}/${ORG_ID}/limits`,
    method: 'PATCH',
    body: { seats: 25, monthly_budget_chf: '250.50', storage_quota: 20 * GIB },
    resolves: ORG_LIMITS,
  },
  {
    name: 'deactivatePlatformOrg',
    call: () => deactivatePlatformOrg(ORG_ID),
    response: () => jsonResponse(200, ORG_DEACTIVATED),
    url: `${ORGS}/${ORG_ID}/deactivate`,
    method: 'POST',
    body: undefined,
    resolves: ORG_DEACTIVATED,
  },
  {
    name: 'reactivatePlatformOrg',
    call: () => reactivatePlatformOrg(ORG_ID),
    response: () => jsonResponse(200, ORG),
    url: `${ORGS}/${ORG_ID}/reactivate`,
    method: 'POST',
    body: undefined,
    resolves: ORG,
  },
  {
    name: 'schedulePlatformOrgDeletion',
    call: () => schedulePlatformOrgDeletion(ORG_ID),
    response: () => jsonResponse(200, ORG_PENDING),
    url: `${ORGS}/${ORG_ID}/deletion`,
    method: 'POST',
    body: undefined,
    resolves: ORG_PENDING,
  },
  {
    name: 'cancelPlatformOrgDeletion',
    call: () => cancelPlatformOrgDeletion(ORG_ID),
    response: () => jsonResponse(200, ORG_DEACTIVATED),
    url: `${ORGS}/${ORG_ID}/deletion`,
    method: 'DELETE',
    body: undefined,
    resolves: ORG_DEACTIVATED,
  },
  {
    name: 'setPlatformOrgResidency (off)',
    call: () => setPlatformOrgResidency(ORG_ID, false),
    response: () => jsonResponse(200, ORG_RESIDENCY_OFF),
    url: `${ORGS}/${ORG_ID}/residency`,
    method: 'PATCH',
    body: { enabled: false },
    resolves: ORG_RESIDENCY_OFF,
  },
  {
    name: 'setPlatformOrgResidency (on)',
    call: () => setPlatformOrgResidency(OTHER_ORG_ID, true),
    response: () => jsonResponse(200, { ...OTHER_ORG, data_residency: true }),
    url: `${ORGS}/${OTHER_ORG_ID}/residency`,
    method: 'PATCH',
    body: { enabled: true },
    resolves: { ...OTHER_ORG, data_residency: true },
  },
  {
    name: 'listPlatformOrgUsers',
    call: () => listPlatformOrgUsers(ORG_ID),
    response: () => jsonResponse(200, USER_LIST),
    url: `${ORGS}/${ORG_ID}/users`,
    method: 'GET',
    body: undefined,
    resolves: USER_LIST,
  },
  {
    name: 'getPlatformOrgMetadata',
    call: () => getPlatformOrgMetadata(ORG_ID),
    response: () => jsonResponse(200, METADATA),
    url: `${ORGS}/${ORG_ID}/metadata`,
    method: 'GET',
    body: undefined,
    resolves: METADATA,
  },
  {
    name: 'deactivatePlatformUser',
    call: () => deactivatePlatformUser(ORG_ID, USER_ID),
    response: () => jsonResponse(200, USER_DEACTIVATED),
    url: `${ORGS}/${ORG_ID}/users/${USER_ID}/deactivate`,
    method: 'POST',
    body: undefined,
    resolves: USER_DEACTIVATED,
  },
  {
    name: 'reactivatePlatformUser',
    call: () => reactivatePlatformUser(ORG_ID, USER_ID),
    response: () => jsonResponse(200, USER),
    url: `${ORGS}/${ORG_ID}/users/${USER_ID}/reactivate`,
    method: 'POST',
    body: undefined,
    resolves: USER,
  },
  {
    name: 'resetPlatformUserPassword',
    call: () => resetPlatformUserPassword(ORG_ID, USER_ID),
    response: () => emptyResponse(202),
    url: `${ORGS}/${ORG_ID}/users/${USER_ID}/password-reset`,
    method: 'POST',
    body: undefined,
    resolves: undefined,
  },
  {
    name: 'reinvitePlatformUser (resend, no email)',
    call: () => reinvitePlatformUser(ORG_ID, ADMIN_ID),
    response: () => jsonResponse(200, REINVITED),
    url: `${ORGS}/${ORG_ID}/users/${ADMIN_ID}/invitation`,
    method: 'POST',
    body: {},
    resolves: REINVITED,
  },
  {
    name: 'reinvitePlatformUser (new email)',
    call: () => reinvitePlatformUser(ORG_ID, ADMIN_ID, 'neu@muster.ch'),
    response: () => jsonResponse(200, { ...REINVITED, email: 'neu@muster.ch' }),
    url: `${ORGS}/${ORG_ID}/users/${ADMIN_ID}/invitation`,
    method: 'POST',
    body: { email: 'neu@muster.ch' },
    resolves: { ...REINVITED, email: 'neu@muster.ch' },
  },
  {
    name: 'getPlatformSettings',
    call: () => getPlatformSettings(),
    response: () => jsonResponse(200, SETTINGS),
    url: '/api/platform/settings',
    method: 'GET',
    body: undefined,
    resolves: SETTINGS,
  },
  {
    name: 'patchPlatformSettings',
    call: () => patchPlatformSettings({ llm: { provider: 'anthropic' }, confirm_residency_orgs: 3 }),
    response: () => jsonResponse(200, SETTINGS_ANTHROPIC),
    url: '/api/platform/settings',
    method: 'PATCH',
    body: { llm: { provider: 'anthropic' }, confirm_residency_orgs: 3 },
    resolves: SETTINGS_ANTHROPIC,
  },
];

describe('platform API requests', () => {
  it.each(REQUEST_CASES)('$name sends $method $url with the expected body', async (c) => {
    fetchMock.mockResolvedValueOnce(c.response());

    await c.call();

    expect(onlyRequest()).toStrictEqual({ url: c.url, method: c.method, body: c.body });
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

  it.each(REQUEST_CASES)('$name only ever requests a path under /api/platform/ (operator blindness)', async (c) => {
    fetchMock.mockResolvedValue(c.response());

    await c.call();

    const urls = fetchMock.mock.calls.map(([url]) => String(url));
    expect({
      requested: urls.length > 0,
      outside: urls.filter((url) => !url.startsWith('/api/platform/')),
    }).toEqual({ requested: true, outside: [] });
  });

  it('resetPlatformUserPassword resolves undefined for a 202 even when the answer carries a body', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'accepted' }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await resetPlatformUserPassword(ORG_ID, USER_ID);

    expect({ calls: fetchMock.mock.calls.length, result }).toEqual({ calls: 1, result: undefined });
  });
});

// --- Exact bodies ---------------------------------------------------------------

describe('createPlatformOrg body', () => {
  it('sends exactly the given request (the five fields, no status added)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, CREATED));

    await createPlatformOrg(CREATE_BODY);

    expect(parsedBody(onlyRawBody())).toStrictEqual({
      name: 'Neue Firma AG',
      primary_admin_email: 'admin@neue-firma.ch',
      seats: 10,
      monthly_budget_chf: '100.00',
      storage_quota: 10 * GIB,
    });
  });

  it('JSON-encodes a name and an email with quotes and non-ASCII characters verbatim', async () => {
    const tricky: PlatformOrgCreateRequest = {
      ...CREATE_BODY,
      name: 'Zoë "Café" & Söhne <AG>',
      primary_admin_email: 'o"brien.zoë@exämple.ch',
    };
    fetchMock.mockResolvedValueOnce(jsonResponse(201, CREATED));

    await createPlatformOrg(tricky);

    expect(onlyRequest()).toStrictEqual({ url: ORGS, method: 'POST', body: tricky });
  });

  it('never puts the name or the email into the URL', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, CREATED));

    await createPlatformOrg(CREATE_BODY);

    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect({ hasEmail: url.includes('neue-firma'), hasName: url.includes('Neue') }).toEqual({
      hasEmail: false,
      hasName: false,
    });
  });
});

describe('updatePlatformOrgLimits body', () => {
  it.each<[string, PlatformOrgLimitsPatch]>([
    ['seats only', { seats: 25 }],
    ['budget only', { monthly_budget_chf: '250.50' }],
    ['storage only', { storage_quota: 0 }],
    ['seats and storage', { seats: 1, storage_quota: 5 * GIB }],
    ['all three', { seats: 100000, monthly_budget_chf: '0.00', storage_quota: 20 * GIB }],
  ])('sends exactly the given patch (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_LIMITS));

    await updatePlatformOrgLimits(ORG_ID, patch);

    expect(onlyRequest()).toStrictEqual({ url: `${ORGS}/${ORG_ID}/limits`, method: 'PATCH', body: patch });
  });
});

describe('setPlatformOrgResidency body', () => {
  it.each([
    [true, '{"enabled":true}'],
    [false, '{"enabled":false}'],
  ])('enabled=%s sends exactly %s', async (enabled, raw) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ...ORG, data_residency: enabled }));

    await setPlatformOrgResidency(ORG_ID, enabled);

    expect(onlyRawBody()).toBe(raw);
  });
});

describe('reinvitePlatformUser body', () => {
  it('without an email sends exactly {} (resend with a new link)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, REINVITED));

    await reinvitePlatformUser(ORG_ID, ADMIN_ID);

    expect(onlyRawBody()).toBe('{}');
  });

  it('with an explicitly undefined email sends exactly {}', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, REINVITED));

    await reinvitePlatformUser(ORG_ID, ADMIN_ID, undefined);

    expect(onlyRawBody()).toBe('{}');
  });

  it('with an email sends exactly {"email": email}', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ...REINVITED, email: 'neu@muster.ch' }));

    await reinvitePlatformUser(ORG_ID, ADMIN_ID, 'neu@muster.ch');

    expect(onlyRawBody()).toBe('{"email":"neu@muster.ch"}');
  });

  it('sends an empty email as given (the backend refuses it; it is never turned into a resend)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: 'Invalid email.' }));

    await thrownBy(() => reinvitePlatformUser(ORG_ID, ADMIN_ID, ''));

    expect(parsedBody(onlyRawBody())).toStrictEqual({ email: '' });
  });

  it('JSON-encodes an email with quotes and non-ASCII characters verbatim and keeps it out of the URL', async () => {
    const tricky = 'o"brien.zoë@exämple.ch';
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ...REINVITED, email: tricky }));

    await reinvitePlatformUser(ORG_ID, ADMIN_ID, tricky);

    const sent = onlyRequest();
    expect({ body: sent.body, urlHasEmail: String(sent.url).includes('brien') }).toStrictEqual({
      body: { email: tricky },
      urlHasEmail: false,
    });
  });
});

describe('patchPlatformSettings body', () => {
  it.each<[string, PlatformSettingsPatch]>([
    ['a Swiss provider switch', { llm: { provider: 'vllm' } }],
    ['a non-Swiss switch with the confirmation count', { llm: { provider: 'openai' }, confirm_residency_orgs: 0 }],
    [
      'model fields only',
      { llm: { infomaniak_model: 'mistral3', max_input_tokens: 64000, image_input: true, max_retries: 0 } },
    ],
    [
      'several sections',
      {
        limits: { max_tool_calls_per_message: 20 },
        files: { render_dpi: 200 },
        retention: { trash_min_days: 0, org_deletion_grace_days: 14 },
        security: { session_idle_timeout_minutes: 30 },
      },
    ],
  ])('sends exactly the given patch (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SETTINGS));

    await patchPlatformSettings(patch);

    expect(onlyRequest()).toStrictEqual({ url: '/api/platform/settings', method: 'PATCH', body: patch });
  });
});

describe('ids', () => {
  it('accepts an upper-case org id (the id check is case-insensitive)', async () => {
    const upper = ORG_ID.toUpperCase();
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_DEACTIVATED));

    await deactivatePlatformOrg(upper);

    expect(onlyRequest()).toStrictEqual({ url: `${ORGS}/${upper}/deactivate`, method: 'POST', body: undefined });
  });

  it('accepts an upper-case user id (the id check is case-insensitive)', async () => {
    const upper = USER_ID.toUpperCase();
    fetchMock.mockResolvedValueOnce(jsonResponse(200, USER_DEACTIVATED));

    await deactivatePlatformUser(ORG_ID, upper);

    expect(onlyRequest()).toStrictEqual({
      url: `${ORGS}/${ORG_ID}/users/${upper}/deactivate`,
      method: 'POST',
      body: undefined,
    });
  });

  it('puts the org id before the user id in the path (they are not swapped)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, USER));

    await reactivatePlatformUser(OTHER_ORG_ID, ADMIN_ID);

    expect(onlyRequest().url).toBe(`${ORGS}/${OTHER_ORG_ID}/users/${ADMIN_ID}/reactivate`);
  });
});

// --- Errors ------------------------------------------------------------------

describe('platform API errors', () => {
  const ERROR_CASES: ReadonlyArray<{
    name: string;
    call: () => Promise<unknown>;
    status: number;
    reason: string | undefined;
    extra?: Record<string, unknown>;
  }> = [
    { name: 'createPlatformOrg (address taken)', call: () => createPlatformOrg(CREATE_BODY), status: 409, reason: 'email_taken' },
    { name: 'createPlatformOrg (invalid)', call: () => createPlatformOrg(CREATE_BODY), status: 422, reason: undefined },
    { name: 'updatePlatformOrgLimits (pending deletion)', call: () => updatePlatformOrgLimits(ORG_ID, { seats: 5 }), status: 409, reason: 'invalid_status' },
    { name: 'updatePlatformOrgLimits (unknown org)', call: () => updatePlatformOrgLimits(ORG_ID, { seats: 5 }), status: 404, reason: undefined },
    { name: 'deactivatePlatformOrg', call: () => deactivatePlatformOrg(ORG_ID), status: 409, reason: 'invalid_status' },
    { name: 'reactivatePlatformOrg', call: () => reactivatePlatformOrg(ORG_ID), status: 409, reason: 'invalid_status' },
    { name: 'schedulePlatformOrgDeletion', call: () => schedulePlatformOrgDeletion(ORG_ID), status: 409, reason: 'invalid_status' },
    { name: 'cancelPlatformOrgDeletion', call: () => cancelPlatformOrgDeletion(ORG_ID), status: 409, reason: 'invalid_status' },
    { name: 'setPlatformOrgResidency', call: () => setPlatformOrgResidency(ORG_ID, false), status: 409, reason: 'invalid_status' },
    { name: 'listPlatformOrgUsers (unknown org)', call: () => listPlatformOrgUsers(ORG_ID), status: 404, reason: undefined },
    { name: 'getPlatformOrgMetadata (unknown org)', call: () => getPlatformOrgMetadata(ORG_ID), status: 404, reason: undefined },
    { name: 'deactivatePlatformUser (last admin)', call: () => deactivatePlatformUser(ORG_ID, USER_ID), status: 409, reason: 'last_admin' },
    { name: 'deactivatePlatformUser (other org)', call: () => deactivatePlatformUser(ORG_ID, USER_ID), status: 404, reason: undefined },
    { name: 'reactivatePlatformUser (no free seat)', call: () => reactivatePlatformUser(ORG_ID, USER_ID), status: 409, reason: 'seat_limit' },
    { name: 'resetPlatformUserPassword (inactive)', call: () => resetPlatformUserPassword(ORG_ID, USER_ID), status: 409, reason: 'invalid_status' },
    { name: 'resetPlatformUserPassword (rate limited)', call: () => resetPlatformUserPassword(ORG_ID, USER_ID), status: 429, reason: undefined },
    { name: 'reinvitePlatformUser (has an active admin)', call: () => reinvitePlatformUser(ORG_ID, ADMIN_ID), status: 409, reason: 'has_active_admin' },
    { name: 'reinvitePlatformUser (address taken)', call: () => reinvitePlatformUser(ORG_ID, ADMIN_ID, 'b@muster.ch'), status: 409, reason: 'email_taken' },
    { name: 'reinvitePlatformUser (no free seat)', call: () => reinvitePlatformUser(ORG_ID, ADMIN_ID, 'c@muster.ch'), status: 409, reason: 'seat_limit' },
    { name: 'listPlatformOrgs (not a Super Admin)', call: () => listPlatformOrgs(), status: 403, reason: undefined },
    { name: 'getPlatformSettings (not a Super Admin)', call: () => getPlatformSettings(), status: 403, reason: undefined },
    {
      name: 'patchPlatformSettings (residency count changed)',
      call: () => patchPlatformSettings({ llm: { provider: 'anthropic' }, confirm_residency_orgs: 2 }),
      status: 409,
      reason: 'residency_confirmation',
      extra: { residency_orgs: 3 },
    },
    { name: 'patchPlatformSettings (invalid)', call: () => patchPlatformSettings({ llm: { max_retries: 9 } }), status: 422, reason: undefined },
  ];

  it.each(ERROR_CASES)('$name rejects $status ($reason) as an ApiError carrying status and reason', async (c) => {
    const detail = `Backend detail text for ${c.name}.`;
    const body: Record<string, unknown> = { detail, ...(c.extra ?? {}) };
    if (c.reason !== undefined) body.reason = c.reason;
    fetchMock.mockResolvedValueOnce(jsonResponse(c.status, body));

    const error = await thrownBy(c.call);

    expect(error).toBeInstanceOf(ApiError);
    expect({
      status: (error as ApiError).status,
      reason: (error as ApiError).reason,
      reasonIsNotTheDetail: (error as ApiError).reason !== detail,
      calls: fetchMock.mock.calls.length,
    }).toEqual({ status: c.status, reason: c.reason, reasonIsNotTheDetail: true, calls: 1 });
  });

  it('a network failure rejects (never resolves a fake success)', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const error = await thrownBy(() => setPlatformOrgResidency(ORG_ID, false));

    expect(error).toBeInstanceOf(TypeError);
  });
});

// --- Path-injection guard ------------------------------------------------------

describe('platform API id guard', () => {
  /** Every function that takes an org id, with valid other arguments. */
  const ORG_ID_FUNCTIONS: ReadonlyArray<[string, (id: string) => Promise<unknown>]> = [
    ['updatePlatformOrgLimits', (id) => updatePlatformOrgLimits(id, { seats: 5 })],
    ['deactivatePlatformOrg', (id) => deactivatePlatformOrg(id)],
    ['reactivatePlatformOrg', (id) => reactivatePlatformOrg(id)],
    ['schedulePlatformOrgDeletion', (id) => schedulePlatformOrgDeletion(id)],
    ['cancelPlatformOrgDeletion', (id) => cancelPlatformOrgDeletion(id)],
    ['setPlatformOrgResidency', (id) => setPlatformOrgResidency(id, true)],
    ['listPlatformOrgUsers', (id) => listPlatformOrgUsers(id)],
    ['getPlatformOrgMetadata', (id) => getPlatformOrgMetadata(id)],
    ['deactivatePlatformUser (org id)', (id) => deactivatePlatformUser(id, USER_ID)],
    ['reactivatePlatformUser (org id)', (id) => reactivatePlatformUser(id, USER_ID)],
    ['resetPlatformUserPassword (org id)', (id) => resetPlatformUserPassword(id, USER_ID)],
    ['reinvitePlatformUser (org id)', (id) => reinvitePlatformUser(id, ADMIN_ID)],
    ['reinvitePlatformUser with email (org id)', (id) => reinvitePlatformUser(id, ADMIN_ID, 'neu@muster.ch')],
  ];

  /** Every function that takes a user id, with a valid org id. */
  const USER_ID_FUNCTIONS: ReadonlyArray<[string, (id: string) => Promise<unknown>]> = [
    ['deactivatePlatformUser (user id)', (id) => deactivatePlatformUser(ORG_ID, id)],
    ['reactivatePlatformUser (user id)', (id) => reactivatePlatformUser(ORG_ID, id)],
    ['resetPlatformUserPassword (user id)', (id) => resetPlatformUserPassword(ORG_ID, id)],
    ['reinvitePlatformUser (user id)', (id) => reinvitePlatformUser(ORG_ID, id)],
    ['reinvitePlatformUser with email (user id)', (id) => reinvitePlatformUser(ORG_ID, id, 'neu@muster.ch')],
  ];

  const BAD_IDS: ReadonlyArray<[string, string]> = [
    ['parent path', '../x'],
    ['slash', 'a/b'],
    ['empty', ''],
    ['UUID with a suffix', `${ORG_ID}x`],
    ['UUID with a trailing path segment', `${ORG_ID}/users`],
    ['UUID behind a parent path', `../${ORG_ID}`],
    ['UUID with a query', `${ORG_ID}?x=1`],
    ['UUID with a fragment', `${ORG_ID}#x`],
    ['UUID with a trailing newline', `${ORG_ID}\n`],
    ['UUID with a leading space', ` ${ORG_ID}`],
    ['encoded dots', '%2e%2e'],
    ['encoded slash', `${ORG_ID}%2f..`],
    ['non-hex character', '3c5e7a90-1b2d-4f6e-8a0c-9d1e2f3a4b5g'],
    ['UUID without dashes', '3c5e7a901b2d4f6e8a0c9d1e2f3a4b5c'],
    ['short word', 'abc'],
  ];

  const ALL_ID_FUNCTIONS = [...ORG_ID_FUNCTIONS, ...USER_ID_FUNCTIONS];

  describe.each(ALL_ID_FUNCTIONS)('%s', (_name, call) => {
    it.each(BAD_IDS)('refuses a %s id with Error("Invalid id") and makes no request', async (_label, id) => {
      fetchMock.mockResolvedValue(jsonResponse(200, ORG));

      const error = await thrownBy(() => call(id));

      expect({
        isError: error instanceof Error,
        isApiError: error instanceof ApiError,
        message: (error as Error).message,
        requests: fetchMock.mock.calls.length,
      }).toEqual({ isError: true, isApiError: false, message: 'Invalid id', requests: 0 });
    });
  });

  it.each(ALL_ID_FUNCTIONS)('%s still sends a request for valid ids (the guard is not a blanket refusal)', async (_name, call) => {
    fetchMock.mockResolvedValue(jsonResponse(200, ORG));

    await call(OTHER_ORG_ID);

    expect(fetchMock.mock.calls.length).toBe(1);
  });
});
