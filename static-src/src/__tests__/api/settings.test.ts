/**
 * Settings API client tests (issue #159: settings split into platform,
 * organization and user scopes).
 *
 * The old single `/api/settings` endpoint is gone, so `@/api/settings` no
 * longer exports `getSettings` / `patchSettings`. It wraps:
 * - `getMySettings()` -> `GET /api/me/settings` (the caller's own theme and
 *   notifications, every role),
 * - `patchMySettings(patch)` -> `PATCH /api/me/settings`,
 * - `getOrgSettings()` -> `GET /api/org/settings` (Org Admin only; anyone else
 *   gets a 403),
 * - `patchOrgSettings(patch)` -> `PATCH /api/org/settings`,
 * - `getOAuthStatus(provider)` -> `GET /api/oauth/{provider}/status`, where
 *   the provider is only ever `google` or `microsoft`. Any other value throws
 *   `Invalid provider` before a request is made, so a crafted value can never
 *   reach another path.
 * `getOAuthAuthorizeUrl` and `disconnectOAuth` keep their paths (regression
 * guards below). Every call goes through `fetchJson`, so it sends the session
 * cookie (`credentials: 'same-origin'`) and a PATCH body is exactly the
 * JSON-encoded patch. No call ever targets `/api/settings`.
 *
 * Issue #162 (per-user connections, residency gating): same functions and
 * paths. The response types change: `OAuthConnectionStatus` gains
 * `data_residency` and its `services` become `{ tool, enabled }` entries (the
 * provider's three services with the org's stored switch), and
 * `OrgSettingsResponse` gains the org's read-only `data_residency`. The
 * client resolves those bodies verbatim (a type change only, so those cases
 * are RED under `npm run typecheck`, not at runtime).
 * `getOAuthAuthorizeUrl(provider)` now validates the provider like
 * `getOAuthStatus`: anything but `google` / `microsoft` throws
 * `Invalid provider` before any request, so a crafted value can never reach
 * another path.
 *
 * Issue #35 (Settings controls: task-done pings, reset my settings):
 * - the user settings carry `notifications.task_done` next to `enabled`, and
 *   `patchMySettings({ notifications: { task_done } })` sends exactly that
 *   JSON body (no `enabled`, no `appearance`). These cases are a type change
 *   only, so they are RED under `npm run typecheck`, not at runtime.
 * - `resetMySettings()` -> `POST /api/me/settings/reset` with the session
 *   cookie and no body. It resolves the parsed body (the defaults) and
 *   rejects a non-2xx (429 rate limit, 403, 401) with an `ApiError` carrying
 *   the status and the backend's `detail`.
 *
 * Issue #169 (Organization profile, policies and instructions; contract
 * GH-169 §7): same functions, paths and signatures. `OrgSettingsResponse`
 * becomes the full settings response (`profile`, `instructions`,
 * `security`, `retention` with the platform bounds, `tools`,
 * `data_residency`, `plan`) and the client resolves it verbatim.
 * `OrgSettingsPatch` gains the optional `profile`, `instructions`,
 * `security` and `retention` sections (`tools` becomes optional), and
 * `patchOrgSettings` sends exactly the given patch as the JSON body (the
 * instructions verbatim, `""` included) with the session cookie; the
 * same-origin CSRF check is server-side, so no extra header is expected. A
 * 400 `{"detail", "reason": "trash_retention_bounds"}` rejects with an
 * `ApiError` carrying the status and that `reason`. The client is a
 * pass-through, so these cases are a type change (RED under
 * `npm run typecheck`, not at runtime).
 *
 * `fetch` is stubbed; nothing touches the network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import * as settingsApi from '@/api/settings';
import {
  disconnectOAuth,
  getMySettings,
  getOAuthAuthorizeUrl,
  getOAuthStatus,
  getOrgSettings,
  patchMySettings,
  patchOrgSettings,
  resetMySettings,
} from '@/api/settings';
import type {
  OAuthConnectionStatus,
  OrgSettingsPatch,
  OrgSettingsResponse,
  UserSettingsPatch,
  UserSettingsResponse,
} from '@/api/types';

const fetchMock = vi.fn<typeof fetch>();

const MY_SETTINGS: UserSettingsResponse = {
  appearance: { theme: 'dark' },
  notifications: { enabled: false, task_done: true },
};

/** What `POST /api/me/settings/reset` returns: the user-scope defaults. */
const DEFAULT_MY_SETTINGS: UserSettingsResponse = {
  appearance: { theme: 'light' },
  notifications: { enabled: true, task_done: false },
};

/** The full org settings response (issue #169's shape; the #162 tools and residency inside it). */
const ORG_SETTINGS: OrgSettingsResponse = {
  profile: { display_name: 'Treuhand Muster AG', default_response_language: 'de' },
  instructions: 'Antworte förmlich.\nNenne nie Kundennamen.',
  security: { session_idle_timeout_minutes: 45, session_max_lifetime_hours: 8 },
  retention: { trash_retention_days: 21, trash_min_days: 7, trash_max_days: 60 },
  tools: {
    gmail: false,
    google_calendar: true,
    google_drive: true,
    outlook: true,
    outlook_calendar: false,
    onedrive: true,
    memory: true,
  },
  data_residency: false,
  plan: { seats: 25, storage_quota: 10_737_418_240 },
};

/** A residency org: its stored switches plus `data_residency: true` (issue #162). */
const RESIDENCY_ORG_SETTINGS: OrgSettingsResponse = {
  profile: { display_name: 'Fiduciaire Exemple SA', default_response_language: 'fr' },
  instructions: '',
  security: { session_idle_timeout_minutes: 15, session_max_lifetime_hours: 72 },
  retention: { trash_retention_days: 0, trash_min_days: 0, trash_max_days: 90 },
  tools: {
    gmail: true,
    google_calendar: false,
    google_drive: true,
    outlook: true,
    outlook_calendar: true,
    onedrive: false,
    memory: false,
  },
  data_residency: true,
  plan: { seats: 3, storage_quota: 1_073_741_824 },
};

/**
 * Contract GH-169 §2: the GET body of a fresh org with no org_settings row
 * (every column default, residency off, platform retention 0..90).
 */
const FRESH_ORG_SETTINGS: OrgSettingsResponse = {
  profile: { display_name: 'Treuhand Muster AG', default_response_language: 'en' },
  instructions: '',
  security: { session_idle_timeout_minutes: 60, session_max_lifetime_hours: 12 },
  retention: { trash_retention_days: 30, trash_min_days: 0, trash_max_days: 90 },
  tools: {
    gmail: true,
    google_calendar: true,
    google_drive: true,
    outlook: true,
    outlook_calendar: true,
    onedrive: true,
    memory: true,
  },
  data_residency: false,
  plan: { seats: 10, storage_quota: 10_737_418_240 },
};

const GOOGLE_STATUS: OAuthConnectionStatus = {
  connected: true,
  healthy: true,
  email: null,
  data_residency: false,
  services: [
    { tool: 'gmail', enabled: true },
    { tool: 'google_calendar', enabled: false },
    { tool: 'google_drive', enabled: true },
  ],
};

/** A residency org's caller with a kept (inactive) Microsoft connection. */
const MICROSOFT_STATUS: OAuthConnectionStatus = {
  connected: true,
  healthy: true,
  email: null,
  data_residency: true,
  services: [
    { tool: 'outlook', enabled: true },
    { tool: 'outlook_calendar', enabled: true },
    { tool: 'onedrive', enabled: false },
  ],
};

const DISCONNECTED_STATUS: OAuthConnectionStatus = {
  connected: false,
  healthy: false,
  email: null,
  data_residency: false,
  services: [
    { tool: 'outlook', enabled: true },
    { tool: 'outlook_calendar', enabled: true },
    { tool: 'onedrive', enabled: true },
  ],
};

/** Provider values a well-behaved caller never passes. */
const INVALID_PROVIDERS = [
  'github',
  '../x',
  '',
  'Google',
  'MICROSOFT',
  'google/../settings',
  'google?x=1',
  '__proto__',
  'constructor',
];

function jsonResponse(status: number, body: unknown, statusText = ''): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText,
    headers: { 'Content-Type': 'application/json' },
  });
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

/** The request of the only fetch call, in a comparable shape. */
function sentRequest(): { method: string; url: string; body: unknown; credentials: unknown } {
  const { url, init } = sent();
  return { method: methodOf(init), url, body: bodyOf(init), credentials: init.credentials };
}

/**
 * Runs `fn` and returns what it threw, whether it threw synchronously or
 * returned a rejected promise. Fails when it succeeds.
 */
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

// --- The old single-scope client is gone ---------------------------------

describe('settings api old /api/settings client removed', () => {
  it.each(['getSettings', 'patchSettings'])('no longer exports %s', (name) => {
    expect(name in settingsApi).toBe(false);
  });

  it('never sends a request to /api/settings from any settings call', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith('/api/me/settings')) return jsonResponse(200, MY_SETTINGS);
      if (url.startsWith('/api/org/settings')) return jsonResponse(200, ORG_SETTINGS);
      if (url.endsWith('/status')) return jsonResponse(200, MICROSOFT_STATUS);
      if (url.endsWith('/authorize')) return jsonResponse(200, { url: 'https://accounts.example/' });
      return jsonResponse(200, { status: 'disconnected' });
    });

    await getMySettings();
    await patchMySettings({ notifications: { enabled: true } });
    await getOrgSettings();
    await patchOrgSettings({ tools: { gmail: true } });
    await getOAuthStatus('google');
    await getOAuthStatus('microsoft');
    await getOAuthAuthorizeUrl('google');
    await disconnectOAuth('microsoft');

    const urls = fetchMock.mock.calls.map(([input]) => String(input));
    expect({
      calls: urls.length,
      legacy: urls.filter((url) => /^\/api\/settings(?:[/?#]|$)/.test(url)),
    }).toEqual({ calls: 8, legacy: [] });
  });
});

// --- User scope: /api/me/settings -----------------------------------------

describe('settings api getMySettings', () => {
  it('sends GET /api/me/settings with the session cookie and no body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    await getMySettings();

    expect(sentRequest()).toEqual({
      method: 'GET',
      url: '/api/me/settings',
      body: undefined,
      credentials: 'same-origin',
    });
  });

  it('resolves the parsed user settings body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    expect(await getMySettings()).toEqual(MY_SETTINGS);
  });

  it('rejects a 401 with an ApiError carrying the status', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Unauthorized' }, 'Unauthorized'));

    const error = await thrownBy(() => getMySettings());

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
  });
});

describe('settings api patchMySettings', () => {
  const patches: Array<[string, UserSettingsPatch]> = [
    ['a theme change', { appearance: { theme: 'system' } }],
    ['a notifications change', { notifications: { enabled: false } }],
    ['both scopes at once', { appearance: { theme: 'dark' }, notifications: { enabled: true } }],
    ['task-done pings on', { notifications: { task_done: true } }],
    ['task-done pings off', { notifications: { task_done: false } }],
    ['both notification flags', { notifications: { enabled: false, task_done: true } }],
  ];

  it.each(patches)('sends PATCH /api/me/settings with exactly the patch as JSON (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    await patchMySettings(patch);

    expect(sentRequest()).toEqual({
      method: 'PATCH',
      url: '/api/me/settings',
      body: patch,
      credentials: 'same-origin',
    });
  });

  it('sends the JSON encoding of the patch unchanged (no extra keys)', async () => {
    const patch: UserSettingsPatch = { notifications: { enabled: true } };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    await patchMySettings(patch);

    expect(sent().init.body).toBe(JSON.stringify(patch));
  });

  it('resolves the stored user settings the server returns', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    expect(await patchMySettings({ appearance: { theme: 'dark' } })).toEqual(MY_SETTINGS);
  });

  it('sends exactly { notifications: { task_done: true } } as the JSON body for a task-done change', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    await patchMySettings({ notifications: { task_done: true } });

    expect(sent().init.body).toBe('{"notifications":{"task_done":true}}');
  });

  it('rejects a 422 with an ApiError carrying the backend message', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { detail: [{ loc: ['body'], msg: 'Value error, Nothing to update', type: 'value_error' }] }),
    );

    const error = await thrownBy(() => patchMySettings({ appearance: {} }));

    expect(error).toBeInstanceOf(ApiError);
    expect({ status: (error as ApiError).status, message: (error as ApiError).message }).toEqual({
      status: 422,
      message: 'Nothing to update',
    });
  });
});

// --- Reset my settings: POST /api/me/settings/reset (issue #35) -----------

describe('settings api resetMySettings', () => {
  it('sends POST /api/me/settings/reset with the session cookie', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, DEFAULT_MY_SETTINGS));

    await resetMySettings();

    const { url, init } = sent();
    expect({ method: methodOf(init), url, credentials: init.credentials }).toEqual({
      method: 'POST',
      url: '/api/me/settings/reset',
      credentials: 'same-origin',
    });
  });

  it('sends no request body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, DEFAULT_MY_SETTINGS));

    await resetMySettings();

    const { body } = sent().init;
    expect(body === undefined || body === null || body === '').toBe(true);
  });

  it('resolves the parsed body the server returns (the defaults)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, DEFAULT_MY_SETTINGS));

    expect(await resetMySettings()).toEqual(DEFAULT_MY_SETTINGS);
  });

  it('resolves whatever settings the server returns, not hard-coded defaults', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MY_SETTINGS));

    expect(await resetMySettings()).toEqual(MY_SETTINGS);
  });

  it.each([
    [429, 'Too Many Requests', 'Rate limit exceeded'],
    [403, 'Forbidden', 'Forbidden'],
    [401, 'Unauthorized', 'Unauthorized'],
    [500, 'Internal Server Error', 'Internal Server Error'],
  ])('rejects a %i with an ApiError carrying the status and the backend detail', async (status, statusText, detail) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(status, { detail }, statusText));

    const error = await thrownBy(() => resetMySettings());

    expect({
      isApiError: error instanceof ApiError,
      status: (error as ApiError).status,
      message: (error as ApiError).message,
      requests: fetchMock.mock.calls.length,
    }).toEqual({ isApiError: true, status, message: detail, requests: 1 });
  });
});

// --- Organization scope: /api/org/settings --------------------------------

describe('settings api getOrgSettings', () => {
  it('sends GET /api/org/settings with the session cookie and no body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await getOrgSettings();

    expect(sentRequest()).toEqual({
      method: 'GET',
      url: '/api/org/settings',
      body: undefined,
      credentials: 'same-origin',
    });
  });

  it('resolves the parsed org tools', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    expect(await getOrgSettings()).toEqual(ORG_SETTINGS);
  });

  it('resolves a residency org\'s data_residency flag with its stored switches (issue #162)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, RESIDENCY_ORG_SETTINGS));

    expect(await getOrgSettings()).toEqual(RESIDENCY_ORG_SETTINGS);
  });

  it('rejects the 403 a non-admin gets with an ApiError carrying the status', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'Forbidden' }, 'Forbidden'));

    const error = await thrownBy(() => getOrgSettings());

    expect(error).toBeInstanceOf(ApiError);
    expect({ status: (error as ApiError).status, message: (error as ApiError).message }).toEqual({
      status: 403,
      message: 'Forbidden',
    });
  });
});

describe('settings api patchOrgSettings', () => {
  const patches: Array<[string, OrgSettingsPatch]> = [
    ['one tool off', { tools: { gmail: false } }],
    ['one tool on', { tools: { memory: true } }],
    ['several tools', { tools: { outlook: false, onedrive: true, google_drive: false } }],
  ];

  it.each(patches)('sends PATCH /api/org/settings with exactly the patch as JSON (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await patchOrgSettings(patch);

    expect(sentRequest()).toEqual({
      method: 'PATCH',
      url: '/api/org/settings',
      body: patch,
      credentials: 'same-origin',
    });
  });

  it('sends the JSON encoding of the patch unchanged (no extra keys)', async () => {
    const patch: OrgSettingsPatch = { tools: { outlook_calendar: false } };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await patchOrgSettings(patch);

    expect(sent().init.body).toBe(JSON.stringify(patch));
  });

  it('resolves the org tools the server returns', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    expect(await patchOrgSettings({ tools: { gmail: false } })).toEqual(ORG_SETTINGS);
  });

  it('resolves the residency flag the server returns with the stored tools (issue #162)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, RESIDENCY_ORG_SETTINGS));

    expect(await patchOrgSettings({ tools: { memory: false } })).toEqual(RESIDENCY_ORG_SETTINGS);
  });

  it('rejects the 403 an Editor gets with an ApiError carrying the status', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'Forbidden' }, 'Forbidden'));

    const error = await thrownBy(() => patchOrgSettings({ tools: { gmail: false } }));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
  });
});

// --- Organization settings: profile, instructions, policies (issue #169) ---

describe('settings api org settings full response (issue #169)', () => {
  it('getOrgSettings resolves the fresh-org contract body unchanged, every section included', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, FRESH_ORG_SETTINGS));

    const result = await getOrgSettings();

    expect({ result, sections: Object.keys(result).sort() }).toStrictEqual({
      result: FRESH_ORG_SETTINGS,
      sections: ['data_residency', 'instructions', 'plan', 'profile', 'retention', 'security', 'tools'],
    });
  });

  it('getOrgSettings resolves stored values verbatim (instructions with line breaks, clamped retention, plan)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    expect(await getOrgSettings()).toStrictEqual(ORG_SETTINGS);
  });

  it('patchOrgSettings resolves the full response the server returns after the change', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, RESIDENCY_ORG_SETTINGS));

    expect(await patchOrgSettings({ retention: { trash_retention_days: 0 } })).toStrictEqual(RESIDENCY_ORG_SETTINGS);
  });
});

describe('settings api patchOrgSettings sections (issue #169)', () => {
  const patches: Array<[string, OrgSettingsPatch]> = [
    ['a display name', { profile: { display_name: 'Muster Treuhand GmbH' } }],
    ['a response language', { profile: { default_response_language: 'it' } }],
    ['the whole profile', { profile: { display_name: 'Neue AG', default_response_language: 'fr' } }],
    ['new instructions', { instructions: 'Antworte kurz.\nNenne nie Kundennamen.' }],
    ['cleared instructions', { instructions: '' }],
    ['an idle timeout', { security: { session_idle_timeout_minutes: 30 } }],
    ['a lifetime', { security: { session_max_lifetime_hours: 24 } }],
    ['the whole security policy', { security: { session_idle_timeout_minutes: 480, session_max_lifetime_hours: 1 } }],
    ['a retention of 0 days', { retention: { trash_retention_days: 0 } }],
    [
      'every section at once',
      {
        profile: { display_name: 'Neue AG', default_response_language: 'en' },
        instructions: 'Réponds poliment.',
        security: { session_idle_timeout_minutes: 15, session_max_lifetime_hours: 72 },
        retention: { trash_retention_days: 90 },
        tools: { memory: false },
      },
    ],
  ];

  it.each(patches)('sends PATCH /api/org/settings with exactly the patch as JSON (%s)', async (_label, patch) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await patchOrgSettings(patch);

    expect({ request: sentRequest(), rawBody: sent().init.body }).toStrictEqual({
      request: { method: 'PATCH', url: '/api/org/settings', body: patch, credentials: 'same-origin' },
      rawBody: JSON.stringify(patch),
    });
  });

  it('sends cleared instructions as exactly {"instructions":""}', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await patchOrgSettings({ instructions: '' });

    expect(sent().init.body).toBe('{"instructions":""}');
  });

  it('sends the instructions verbatim (surrounding whitespace, tabs, line breaks, umlauts)', async () => {
    const instructions = '  Antworte förmlich.\r\n\tNenne nie Kundennamen.\n\n';
    fetchMock.mockResolvedValueOnce(jsonResponse(200, ORG_SETTINGS));

    await patchOrgSettings({ instructions });

    expect(JSON.parse(String(sent().init.body))).toStrictEqual({ instructions });
  });

  it('rejects the 400 trash bounds refusal with an ApiError carrying the status and the reason', async () => {
    const detail = "The trash retention must be within the platform's bounds.";
    fetchMock.mockResolvedValueOnce(jsonResponse(400, { detail, reason: 'trash_retention_bounds' }, 'Bad Request'));

    const error = await thrownBy(() => patchOrgSettings({ retention: { trash_retention_days: 90 } }));

    expect({
      isApiError: error instanceof ApiError,
      status: (error as ApiError).status,
      reason: (error as ApiError).reason,
      message: (error as ApiError).message,
      requests: fetchMock.mock.calls.length,
    }).toEqual({ isApiError: true, status: 400, reason: 'trash_retention_bounds', message: detail, requests: 1 });
  });

  it('rejects a 422 refusal (a read-only field named) with an ApiError and no reason', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { detail: [{ loc: ['body', 'data_residency'], msg: 'Extra inputs are not permitted', type: 'extra_forbidden' }] }),
    );

    const error = await thrownBy(() => patchOrgSettings({ instructions: 'x' }));

    expect({
      isApiError: error instanceof ApiError,
      status: (error as ApiError).status,
      reason: (error as ApiError).reason,
    }).toEqual({ isApiError: true, status: 422, reason: undefined });
  });

  it('rejects the per-user rate limit 429 with an ApiError carrying the status', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { detail: 'Rate limit exceeded' }, 'Too Many Requests'));

    const error = await thrownBy(() => patchOrgSettings({ security: { session_idle_timeout_minutes: 30 } }));

    expect({ isApiError: error instanceof ApiError, status: (error as ApiError).status }).toEqual({
      isApiError: true,
      status: 429,
    });
  });
});

// --- OAuth connection status ----------------------------------------------

describe('settings api getOAuthStatus', () => {
  it.each([
    ['google', GOOGLE_STATUS],
    ['microsoft', MICROSOFT_STATUS],
    ['microsoft', DISCONNECTED_STATUS],
  ] as const)('sends GET /api/oauth/%s/status and resolves the parsed status', async (provider, status) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, status));

    const result = await getOAuthStatus(provider);

    expect({ request: sentRequest(), result }).toEqual({
      request: {
        method: 'GET',
        url: `/api/oauth/${provider}/status`,
        body: undefined,
        credentials: 'same-origin',
      },
      result: status,
    });
  });

  it.each(INVALID_PROVIDERS)(
    'throws "Invalid provider" for %j without sending any request',
    async (provider) => {
      const error = await thrownBy(() => getOAuthStatus(provider as 'google'));

      expect({
        isError: error instanceof Error,
        message: (error as Error).message,
        requests: fetchMock.mock.calls.length,
      }).toEqual({ isError: true, message: 'Invalid provider', requests: 0 });
    },
  );
});

// --- OAuth authorize (issue #162: the provider is validated) ---------------

describe('settings api getOAuthAuthorizeUrl', () => {
  it.each(['google', 'microsoft'] as const)(
    'sends GET /api/oauth/%s/authorize and resolves the url',
    async (provider) => {
      fetchMock.mockResolvedValueOnce(jsonResponse(200, { url: 'https://login.example/authorize' }));

      const result = await getOAuthAuthorizeUrl(provider);

      expect({ request: sentRequest(), result }).toEqual({
        request: {
          method: 'GET',
          url: `/api/oauth/${provider}/authorize`,
          body: undefined,
          credentials: 'same-origin',
        },
        result: { url: 'https://login.example/authorize' },
      });
    },
  );

  it.each(INVALID_PROVIDERS)(
    'throws "Invalid provider" for %j without sending any request',
    async (provider) => {
      fetchMock.mockResolvedValue(jsonResponse(200, { url: 'https://login.example/authorize' }));

      const error = await thrownBy(() => getOAuthAuthorizeUrl(provider as 'google'));

      expect({
        isError: error instanceof Error,
        message: (error as Error).message,
        requests: fetchMock.mock.calls.length,
      }).toEqual({ isError: true, message: 'Invalid provider', requests: 0 });
    },
  );

  it('rejects the residency 403 with an ApiError carrying the explanation', async () => {
    const detail = "Your organization's data residency policy doesn't allow Google or Microsoft accounts.";
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail }, 'Forbidden'));

    const error = await thrownBy(() => getOAuthAuthorizeUrl('google'));

    expect({
      isApiError: error instanceof ApiError,
      status: (error as ApiError).status,
      message: (error as ApiError).message,
    }).toEqual({ isApiError: true, status: 403, message: detail });
  });
});

// --- Unchanged OAuth calls (regression guards) ----------------------------

describe('settings api unchanged oauth calls', () => {

  it('disconnectOAuth sends DELETE /api/oauth/{provider}', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { status: 'disconnected' }));

    await disconnectOAuth('google');

    expect(sentRequest()).toEqual({
      method: 'DELETE',
      url: '/api/oauth/google',
      body: undefined,
      credentials: 'same-origin',
    });
  });

  it('disconnectOAuth rejects an unknown provider without sending any request', async () => {
    const error = await thrownBy(() => disconnectOAuth('github' as 'google'));

    expect({ message: (error as Error).message, requests: fetchMock.mock.calls.length }).toEqual({
      message: 'Invalid provider',
      requests: 0,
    });
  });
});
