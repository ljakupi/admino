/**
 * Auth page flow tests (issue #155: "errors are generic where the backend is
 * generic"; error responses are never echoed).
 *
 * `@/services/authFlows` holds the logic the Forgot password, Reset
 * password, Accept invitation and Login pages call. Each flow returns a
 * result object and never throws; a failure carries only a catalog key,
 * never text from the server's body:
 *
 * - `requestReset(email)`: always `{ ok: true }` when the request is
 *   accepted (the page shows the same "if an account exists" confirmation
 *   for every email, like the backend's constant 202); 429 → rate limited;
 *   anything else → generic.
 * - `confirmReset(token, newPassword)`: 400 → invalid link; 422 → the policy
 *   key for its `reason`; 429 → rate limited; else generic.
 * - `loadInvitation(token)`: `{ ok: true, invitation }`; 404 → invalid link;
 *   429 → rate limited; else generic.
 * - `acceptInvite(token, name, password)`: 404 → invalid link; 422 with a
 *   policy reason → its policy key; 422 without a reason (the name failed
 *   validation) → invalid name; 429 → rate limited; else generic.
 * - `loginMessageKey(outcome)` maps the auth store's login outcome to a key;
 *   the wrong-credentials text is the backend's generic one.
 *
 * `@/api/auth` is mocked; error cases use the real `ApiError` class.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  acceptInvitation,
  confirmPasswordReset,
  getInvitation,
  requestPasswordReset,
} from '@/api/auth';
import { ApiError } from '@/api/client';
import { setLocale, t, type MessageKey } from '@/i18n';
import { en } from '@/i18n/locales/en';
import {
  acceptInvite,
  confirmReset,
  loadInvitation,
  loginMessageKey,
  requestReset,
} from '@/services/authFlows';
import type { InvitationDetails } from '@/api/types';

vi.mock('@/api/auth', () => ({
  login: vi.fn(),
  logout: vi.fn(),
  getMe: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  getInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

const mockedRequestReset = vi.mocked(requestPasswordReset);
const mockedConfirmReset = vi.mocked(confirmPasswordReset);
const mockedGetInvitation = vi.mocked(getInvitation);
const mockedAcceptInvitation = vi.mocked(acceptInvitation);

const TOKEN = 'k3Jd8_Xq-2mPz7Lw9vRt4NcY6hBf1GsQa5EuWo0TiZy';
const EMAIL = 'alice@example.ch';
const PASSWORD = 'Plumbago-Lantern-4417';
const HOSTILE = '<img src=x onerror=alert(1)>';

const INVITATION: InvitationDetails = { org_name: 'Muster AG', role: 'editor', email: 'bob@example.ch' };

const RATE_LIMITED = 'auth.error.rateLimited';
const GENERIC = 'auth.error.generic';
const RESET_INVALID_LINK = 'auth.reset.error.invalidLink';
const INVITATION_INVALID_LINK = 'auth.invitation.error.invalidLink';
const INVALID_NAME = 'auth.invitation.error.invalidName';

const POLICY_KEYS: Array<[string, string]> = [
  ['too_short', 'auth.password.error.tooShort'],
  ['too_long', 'auth.password.error.tooLong'],
  ['common', 'auth.password.error.common'],
  ['equals_email', 'auth.password.error.equalsEmail'],
];

function apiError(status: number, message = 'backend says no', reason?: string): ApiError {
  return new ApiError(status, 'Status', message, reason);
}

beforeEach(() => {
  mockedRequestReset.mockReset();
  mockedConfirmReset.mockReset();
  mockedGetInvitation.mockReset();
  mockedAcceptInvitation.mockReset();
});

afterEach(() => {
  setLocale('en');
});

// --- requestReset ---------------------------------------------------------

describe('authFlows requestReset', () => {
  it('requests the reset for the email and reports ok', async () => {
    mockedRequestReset.mockResolvedValueOnce(undefined);

    const result = await requestReset(EMAIL);

    expect({ result, calls: mockedRequestReset.mock.calls }).toEqual({ result: { ok: true }, calls: [[EMAIL]] });
  });

  it('reports the same ok for every email (no account enumeration)', async () => {
    mockedRequestReset.mockResolvedValue(undefined);

    const results = [await requestReset('known@example.ch'), await requestReset('nobody@example.ch')];

    expect(results).toEqual([{ ok: true }, { ok: true }]);
  });

  it.each([
    ['a 429', () => apiError(429), RATE_LIMITED],
    ['a 500', () => apiError(500), GENERIC],
    ['a 422', () => apiError(422), GENERIC],
    ['a network failure', () => new TypeError('Failed to fetch'), GENERIC],
  ] as Array<[string, () => Error, string]>)('maps %s to %s and never throws', async (_label, makeError, key) => {
    mockedRequestReset.mockRejectedValueOnce(makeError());

    await expect(requestReset(EMAIL)).resolves.toEqual({ ok: false, messageKey: key });
  });
});

// --- confirmReset ---------------------------------------------------------

describe('authFlows confirmReset', () => {
  it('confirms with the token and the new password and reports ok', async () => {
    mockedConfirmReset.mockResolvedValueOnce(undefined);

    const result = await confirmReset(TOKEN, PASSWORD);

    expect({ result, calls: mockedConfirmReset.mock.calls }).toEqual({
      result: { ok: true },
      calls: [[TOKEN, PASSWORD]],
    });
  });

  it.each([
    ['a 400 (invalid or expired link)', () => apiError(400), RESET_INVALID_LINK],
    ['a 422 without a reason', () => apiError(422), 'auth.password.error.generic'],
    ['a 429', () => apiError(429), RATE_LIMITED],
    ['a 404', () => apiError(404), GENERIC],
    ['a 500', () => apiError(500), GENERIC],
    ['a network failure', () => new TypeError('Failed to fetch'), GENERIC],
  ] as Array<[string, () => Error, string]>)('maps %s to %s and never throws', async (_label, makeError, key) => {
    mockedConfirmReset.mockRejectedValueOnce(makeError());

    await expect(confirmReset(TOKEN, PASSWORD)).resolves.toEqual({ ok: false, messageKey: key });
  });

  it.each(POLICY_KEYS)('maps a 422 with reason %s to %s', async (reason, key) => {
    mockedConfirmReset.mockRejectedValueOnce(apiError(422, 'policy text from the server', reason));

    await expect(confirmReset(TOKEN, PASSWORD)).resolves.toEqual({ ok: false, messageKey: key });
  });
});

// --- loadInvitation -------------------------------------------------------

describe('authFlows loadInvitation', () => {
  it('loads the invitation for the token and returns its details', async () => {
    mockedGetInvitation.mockResolvedValueOnce(INVITATION);

    const result = await loadInvitation(TOKEN);

    expect({ result, calls: mockedGetInvitation.mock.calls }).toEqual({
      result: { ok: true, invitation: INVITATION },
      calls: [[TOKEN]],
    });
  });

  it.each([
    ['a 404 (invalid or expired link)', () => apiError(404), INVITATION_INVALID_LINK],
    ['a 429', () => apiError(429), RATE_LIMITED],
    ['a 400', () => apiError(400), GENERIC],
    ['a 500', () => apiError(500), GENERIC],
    ['a network failure', () => new TypeError('Failed to fetch'), GENERIC],
  ] as Array<[string, () => Error, string]>)('maps %s to %s and never throws', async (_label, makeError, key) => {
    mockedGetInvitation.mockRejectedValueOnce(makeError());

    await expect(loadInvitation(TOKEN)).resolves.toEqual({ ok: false, messageKey: key });
  });
});

// --- acceptInvite ---------------------------------------------------------

describe('authFlows acceptInvite', () => {
  it('accepts with the token, name and password and reports ok', async () => {
    mockedAcceptInvitation.mockResolvedValueOnce(undefined);

    const result = await acceptInvite(TOKEN, 'Bob Muster', PASSWORD);

    expect({ result, calls: mockedAcceptInvitation.mock.calls }).toEqual({
      result: { ok: true },
      calls: [[TOKEN, 'Bob Muster', PASSWORD]],
    });
  });

  it.each([
    ['a 404 (invalid or expired link)', () => apiError(404), INVITATION_INVALID_LINK],
    ['a 422 without a reason (invalid name)', () => apiError(422, 'String should have at least 1 character'), INVALID_NAME],
    ['a 429', () => apiError(429), RATE_LIMITED],
    ['a 400', () => apiError(400), GENERIC],
    ['a 500', () => apiError(500), GENERIC],
    ['a network failure', () => new TypeError('Failed to fetch'), GENERIC],
  ] as Array<[string, () => Error, string]>)('maps %s to %s and never throws', async (_label, makeError, key) => {
    mockedAcceptInvitation.mockRejectedValueOnce(makeError());

    await expect(acceptInvite(TOKEN, 'Bob', PASSWORD)).resolves.toEqual({ ok: false, messageKey: key });
  });

  it.each(POLICY_KEYS)('maps a 422 with reason %s to %s', async (reason, key) => {
    mockedAcceptInvitation.mockRejectedValueOnce(apiError(422, 'policy text from the server', reason));

    await expect(acceptInvite(TOKEN, 'Bob', PASSWORD)).resolves.toEqual({ ok: false, messageKey: key });
  });
});

// --- loginMessageKey ------------------------------------------------------

describe('authFlows loginMessageKey', () => {
  it.each([
    ['invalid', 'auth.login.error.invalid'],
    ['rate_limited', RATE_LIMITED],
    ['error', GENERIC],
  ] as Array<['invalid' | 'rate_limited' | 'error', string]>)('maps %s to %s', (outcome, key) => {
    expect(loginMessageKey(outcome)).toBe(key);
  });
});

// --- Generic, catalog-only messages --------------------------------------

describe('authFlows messages', () => {
  it.each([
    ['auth.login.error.invalid', 'Invalid email or password'],
    ['auth.invitation.error.invalidLink', 'This invitation link is invalid or has expired.'],
    ['auth.reset.error.invalidLink', 'This reset link is invalid or has expired.'],
  ])('words %s exactly like the backend under en: %j', (key, text) => {
    setLocale('en');

    expect(t(key as MessageKey)).toBe(text);
  });

  it('never passes a server message through: a hostile body still yields only a catalog key', async () => {
    mockedRequestReset.mockRejectedValueOnce(apiError(500, HOSTILE));
    mockedConfirmReset.mockRejectedValueOnce(apiError(400, HOSTILE));
    mockedGetInvitation.mockRejectedValueOnce(apiError(404, HOSTILE));
    mockedAcceptInvitation.mockRejectedValueOnce(apiError(422, HOSTILE));

    const results = [
      await requestReset(EMAIL),
      await confirmReset(TOKEN, PASSWORD),
      await loadInvitation(TOKEN),
      await acceptInvite(TOKEN, 'Bob', PASSWORD),
    ];

    expect({ results, leaked: JSON.stringify(results).includes('<img') }).toStrictEqual({
      results: [
        { ok: false, messageKey: GENERIC },
        { ok: false, messageKey: RESET_INVALID_LINK },
        { ok: false, messageKey: INVITATION_INVALID_LINK },
        { ok: false, messageKey: INVALID_NAME },
      ],
      leaked: false,
    });
  });

  it('never passes a hostile reason through either', async () => {
    mockedConfirmReset.mockRejectedValueOnce(apiError(422, HOSTILE, HOSTILE));
    mockedAcceptInvitation.mockRejectedValueOnce(apiError(422, HOSTILE, '__proto__'));

    const results = [await confirmReset(TOKEN, PASSWORD), await acceptInvite(TOKEN, 'Bob', PASSWORD)];

    expect(JSON.stringify(results).includes('<img') || results.some((r) => r.ok)).toBe(false);
  });

  it.each(['en', 'de', 'fr'])('resolves every key the flows produce under %s', async (target) => {
    const produced = new Set<string>([
      loginMessageKey('invalid'),
      loginMessageKey('rate_limited'),
      loginMessageKey('error'),
      RESET_INVALID_LINK,
      INVITATION_INVALID_LINK,
      INVALID_NAME,
      ...POLICY_KEYS.map(([, key]) => key),
      'auth.password.error.generic',
    ]);
    mockedConfirmReset.mockRejectedValueOnce(apiError(400));
    mockedAcceptInvitation.mockRejectedValueOnce(apiError(422));
    mockedGetInvitation.mockRejectedValueOnce(apiError(429));
    for (const result of [
      await confirmReset(TOKEN, PASSWORD),
      await acceptInvite(TOKEN, 'Bob', PASSWORD),
      await loadInvitation(TOKEN),
    ]) {
      if (!result.ok) produced.add(result.messageKey);
    }
    setLocale(target);

    const missing = [...produced].filter((key) => {
      const text = t(key as MessageKey);
      return !Object.hasOwn(en, key) || text === key || text.trim() === '';
    });

    expect(missing).toEqual([]);
  });
});
