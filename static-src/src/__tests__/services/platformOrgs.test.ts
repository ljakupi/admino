/**
 * Platform organizations pure services tests (issue #168: Platform console UI
 * for the Super Admin; V1 rescope: an Organizations tab with an org detail
 * view, and a Defaults tab).
 *
 * `@/services/platformOrgs` holds the framework-free logic the Organizations
 * tab, the org detail view and their stores share (contract GH-168, "Pure
 * services: src/services/platformOrgs.ts"):
 * - constants: `GIB`, the seat bounds, `STORAGE_GIB_MAX` (the largest whole
 *   GiB whose byte count the API still accepts: 2**53 - 1) and the create
 *   form's defaults (the CLI's: 10 seats, CHF 100, 10 GiB);
 * - `PLATFORM_TABS` is exactly orgs and defaults (V1: no models, usage or
 *   audit tab); `platformTabFrom` maps the `?tab=` value; `orgIdFrom` keeps
 *   only a UUID string for `?org=` (arrays, numbers, traversal strings and
 *   '' -> null, so nothing else can reach an `/api/platform/orgs/{id}` path);
 * - the org and user status label keys;
 * - `orgActions` per org status and `userActions` per user and org status, in
 *   a fixed order, failing closed (an unknown status offers nothing; a
 *   re-invitation only for an invited Org Admin of an active org that has no
 *   active Org Admin);
 * - units: `bytesToGib` / `gibToBytes`, and `parseChf` / `toChfString` with
 *   exact integer cents (no float drift);
 * - `buildCreateOrgRequest` (each field's rule and message, every invalid
 *   field reported at once, the exact 5-key body: trimmed name and email, the
 *   budget as a two-decimal string, storage in bytes, never a `status`);
 *   `limitsInputFrom` / `buildLimitsPatch` (only the changed fields are
 *   validated and sent; the budget is compared by value; nothing changed ->
 *   `{ ok: true, value: null }`);
 * - `platformErrorMessage`: reason first, then status, per subject (org,
 *   user, settings); it NEVER returns the backend's `detail` nor the error's
 *   message (#139 §5: error responses are never echoed);
 * - `orgConfirmCopy` / `userConfirmCopy`: the catalog copy with `{name}`
 *   substituted literally and the destructive flags.
 *
 * Expected strings are read from the real en/de/fr catalogs and interpolated
 * here, never hard-coded. Security notes: operator blindness (metadata only)
 * and no echo of error responses; nothing here may write to the console. No
 * component is mounted and nothing touches the network.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import type { OrgStatus, PlatformOrg, PlatformUser, PlatformUserStatus } from '@/api/types';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import type { ConfirmCopy } from '@/services/orgUsers';
import {
  CREATE_DEFAULTS,
  GIB,
  ORG_STATUS_LABEL_KEYS,
  PLATFORM_TABS,
  SEATS_MAX,
  SEATS_MIN,
  STORAGE_GIB_MAX,
  USER_STATUS_LABEL_KEYS,
  buildCreateOrgRequest,
  buildLimitsPatch,
  bytesToGib,
  gibToBytes,
  limitsInputFrom,
  orgActions,
  orgConfirmCopy,
  orgIdFrom,
  parseChf,
  platformErrorMessage,
  platformTabFrom,
  toChfString,
  userActions,
  userConfirmCopy,
  type OrgAction,
  type OrgConfirmKind,
  type OrgCreateInput,
  type OrgFormField,
  type OrgLimitsInput,
  type UserAction,
  type UserConfirmKind,
} from '@/services/platformOrgs';

type CatalogLocale = 'en' | 'de' | 'fr';
type Subject = 'org' | 'user' | 'settings';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/**
 * The catalog's own string for `key` with its `{param}`s filled in one pass
 * (the same literal, never re-expanded substitution `t` does). Throws when the
 * catalog has no non-blank string for the key, so a missing key never makes a
 * comparison vacuous.
 */
function catalogText(
  locale: CatalogLocale,
  key: string,
  params: Record<string, string | number> = {},
): string {
  const catalog = CATALOGS[locale];
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`test setup: the ${locale} catalog has no text for ${key}`);
  }
  return value.replace(PLACEHOLDER, (match: string, name: string): string =>
    Object.hasOwn(params, name) ? String(params[name]) : match,
  );
}

/** Wraps each value in its own tuple: it.each would spread a bare array case. */
function wrap(values: unknown[]): Array<[unknown]> {
  return values.map((value): [unknown] => [value]);
}

const SECRET_DETAIL = 'SECRET detail <script>alert(1)</script>';

function apiError(status: number, reason?: string, detail: string = SECRET_DETAIL): ApiError {
  return new ApiError(status, 'Status', detail, reason);
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

// --- Fixtures ----------------------------------------------------------------------

/** Pinned here (not read from GIB) so the unit helpers aren't checked against themselves. */
const GIB_BYTES = 1_073_741_824;

const ORG_ID = '7d9f3c2a-1b4e-4c6d-8a9f-0e1d2c3b4a59';

function org(overrides: Partial<PlatformOrg> = {}): PlatformOrg {
  return {
    id: ORG_ID,
    name: 'Muster AG',
    status: 'active',
    seats: 10,
    monthly_budget_chf: '100.00',
    storage_quota: 10 * GIB_BYTES,
    data_residency: false,
    deletion_requested_at: null,
    purge_after: null,
    created_at: '2026-09-01T08:00:00Z',
    updated_at: '2026-09-15T08:00:00Z',
    ...overrides,
  };
}

function platformUser(overrides: Partial<PlatformUser> & Pick<PlatformUser, 'id'>): PlatformUser {
  return {
    name: null,
    email: 'someone@muster.ch',
    role: 'editor',
    status: 'active',
    created_at: '2026-09-01T08:00:00Z',
    last_login_at: null,
    ...overrides,
  };
}

const ADMIN_ACTIVE = platformUser({
  id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
  name: 'Alice Muster',
  email: 'alice@muster.ch',
  role: 'org_admin',
  status: 'active',
  last_login_at: '2026-10-01T07:30:00Z',
});
const ADMIN_DEACTIVATED = platformUser({
  id: '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
  email: 'bruno@muster.ch',
  role: 'org_admin',
  status: 'deactivated',
});
const ADMIN_INVITED = platformUser({
  id: '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a',
  email: 'carla@muster.ch',
  role: 'org_admin',
  status: 'invited',
});
const ADMIN_INVITED_OTHER = platformUser({
  id: '3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b',
  email: 'dora@muster.ch',
  role: 'org_admin',
  status: 'invited',
});
const EDITOR_ACTIVE = platformUser({
  id: '4f5a6b7c-8d9e-4f0a-9b2c-3d4e5f6a7b8c',
  name: 'Emile Zuercher',
  email: 'emile@muster.ch',
  role: 'editor',
  status: 'active',
});
const EDITOR_DEACTIVATED = platformUser({
  id: '5a6b7c8d-9e0f-4a1b-8c3d-4e5f6a7b8c9d',
  email: 'fabienne@muster.ch',
  role: 'editor',
  status: 'deactivated',
});
const EDITOR_INVITED = platformUser({
  id: '6b7c8d9e-0f1a-4b2c-9d4e-5f6a7b8c9d0e',
  email: 'gian@muster.ch',
  role: 'editor',
  status: 'invited',
});
const VIEWER_INVITED = platformUser({
  id: '7c8d9e0f-1a2b-4c3d-8e5f-6a7b8c9d0e1f',
  email: 'hanna@muster.ch',
  role: 'viewer',
  status: 'invited',
});

/** An org whose only Org Admins are deactivated or invited: nobody can administer it. */
const NO_ACTIVE_ADMIN: readonly PlatformUser[] = Object.freeze([
  ADMIN_INVITED,
  ADMIN_DEACTIVATED,
  ADMIN_INVITED_OTHER,
  EDITOR_ACTIVE,
  EDITOR_DEACTIVATED,
  EDITOR_INVITED,
  VIEWER_INVITED,
]);

const WITH_ACTIVE_ADMIN: readonly PlatformUser[] = Object.freeze([...NO_ACTIVE_ADMIN, ADMIN_ACTIVE]);

// --- Constants ------------------------------------------------------------------------

describe('platformOrgs constants', () => {
  it('pins GIB, the seat and storage bounds and the create defaults', () => {
    expect({ GIB, SEATS_MIN, SEATS_MAX, STORAGE_GIB_MAX, CREATE_DEFAULTS: { ...CREATE_DEFAULTS } }).toStrictEqual({
      GIB: GIB_BYTES,
      SEATS_MIN: 1,
      SEATS_MAX: 100000,
      STORAGE_GIB_MAX: 8388607,
      CREATE_DEFAULTS: { seats: 10, budgetChf: '100', storageGib: 10 },
    });
  });

  it('STORAGE_GIB_MAX is the largest whole GiB whose bytes stay within 2**53 - 1 (the API bound)', () => {
    expect([
      gibToBytes(STORAGE_GIB_MAX) <= Number.MAX_SAFE_INTEGER,
      gibToBytes(STORAGE_GIB_MAX + 1) > Number.MAX_SAFE_INTEGER,
    ]).toEqual([true, true]);
  });
});

// --- Tabs and view ------------------------------------------------------------------------

describe('PLATFORM_TABS / platformTabFrom', () => {
  it('offers exactly Organizations and Defaults (no models, usage or audit tab in V1)', () => {
    expect([...PLATFORM_TABS]).toEqual(['orgs', 'defaults']);
  });

  it('maps exactly "defaults" to the Defaults tab', () => {
    expect(platformTabFrom('defaults')).toBe('defaults');
  });

  it.each(
    wrap([
      'orgs',
      'Defaults',
      'DEFAULTS',
      ' defaults',
      'defaults ',
      'models',
      'usage',
      'audit',
      '',
      '__proto__',
      'constructor',
      null,
      undefined,
      1,
      ['defaults'],
      {},
    ]),
  )('maps %j to the Organizations tab', (value) => {
    expect(platformTabFrom(value)).toBe('orgs');
  });
});

describe('orgIdFrom', () => {
  it('returns a UUID string unchanged', () => {
    expect(orgIdFrom(ORG_ID)).toBe(ORG_ID);
  });

  it('accepts an uppercase UUID unchanged (the id rule is case-insensitive)', () => {
    const upper = ORG_ID.toUpperCase();

    expect(orgIdFrom(upper)).toBe(upper);
  });

  it.each(
    wrap([
      '',
      '../x',
      '..%2Fx',
      `../${ORG_ID}`,
      `${ORG_ID}/`,
      `${ORG_ID}/../users`,
      `${ORG_ID}?x=1`,
      `${ORG_ID}\n`,
      ` ${ORG_ID}`,
      `${ORG_ID} `,
      `{${ORG_ID}}`,
      ORG_ID.replace(/-/g, ''),
      ORG_ID.slice(0, -1),
      `${ORG_ID}0`,
      ORG_ID.replace('7d9f', '7d9g'),
      '7d9f3c2a1-b4e-4c6d-8a9f-0e1d2c3b4a59',
      '__proto__',
      [ORG_ID],
      [ORG_ID, ORG_ID],
      123,
      null,
      undefined,
      {},
    ]),
  )('refuses %j', (value) => {
    expect(orgIdFrom(value)).toBeNull();
  });
});

// --- Labels ------------------------------------------------------------------------------

describe('status label keys', () => {
  it('maps every org status to its platform.orgs.status.* key', () => {
    expect({ ...ORG_STATUS_LABEL_KEYS }).toStrictEqual({
      active: 'platform.orgs.status.active',
      deactivated: 'platform.orgs.status.deactivated',
      pending_deletion: 'platform.orgs.status.pendingDeletion',
    });
  });

  it('maps every platform user status to its platform.users.status.* key', () => {
    expect({ ...USER_STATUS_LABEL_KEYS }).toStrictEqual({
      active: 'platform.users.status.active',
      deactivated: 'platform.users.status.deactivated',
      invited: 'platform.users.status.invited',
    });
  });

  it.each(LOCALES)('every status label key has %s catalog text', (locale) => {
    const keys: string[] = [...Object.values(ORG_STATUS_LABEL_KEYS), ...Object.values(USER_STATUS_LABEL_KEYS)];

    expect(keys.map((key) => catalogText(locale, key).trim() !== '')).toEqual(keys.map(() => true));
  });
});

// --- Org actions -----------------------------------------------------------------------------

describe('orgActions', () => {
  const ROWS: Array<[OrgStatus, OrgAction[]]> = [
    ['active', ['editLimits', 'deactivate', 'scheduleDeletion', 'residency']],
    ['deactivated', ['editLimits', 'reactivate', 'scheduleDeletion', 'residency']],
    ['pending_deletion', ['cancelDeletion']],
  ];

  it.each(ROWS)('a %s org offers %j, in that order', (status, actions) => {
    expect(orgActions(org({ status }))).toEqual(actions);
  });

  it.each(ROWS)('a status-only %s object gets the same actions', (status, actions) => {
    expect(orgActions({ status })).toEqual(actions);
  });

  it.each(
    wrap([
      'deleted',
      'purged',
      '',
      'ACTIVE',
      'Active',
      ' active',
      'pending-deletion',
      '__proto__',
      'constructor',
      'toString',
      'hasOwnProperty',
      null,
      undefined,
    ]),
  )('fails closed for the unknown status %j (no action at all)', (status) => {
    expect(orgActions({ status: status as OrgStatus })).toEqual([]);
  });
});

// --- User actions ----------------------------------------------------------------------------

describe('userActions', () => {
  const ROWS: Array<[string, PlatformUser, OrgStatus, readonly PlatformUser[], UserAction[]]> = [
    ['an active editor of an active org', EDITOR_ACTIVE, 'active', WITH_ACTIVE_ADMIN, ['deactivate', 'resetPassword']],
    ['an active Org Admin of an active org', ADMIN_ACTIVE, 'active', WITH_ACTIVE_ADMIN, ['deactivate', 'resetPassword']],
    ['an active user of a deactivated org', EDITOR_ACTIVE, 'deactivated', WITH_ACTIVE_ADMIN, ['deactivate']],
    ['an active user of an org pending deletion', EDITOR_ACTIVE, 'pending_deletion', WITH_ACTIVE_ADMIN, ['deactivate']],
    ['a deactivated editor of an active org', EDITOR_DEACTIVATED, 'active', WITH_ACTIVE_ADMIN, ['reactivate']],
    ['a deactivated Org Admin of an active org', ADMIN_DEACTIVATED, 'active', NO_ACTIVE_ADMIN, ['reactivate']],
    ['a deactivated user of a deactivated org', EDITOR_DEACTIVATED, 'deactivated', WITH_ACTIVE_ADMIN, ['reactivate']],
    ['a deactivated user of an org pending deletion', EDITOR_DEACTIVATED, 'pending_deletion', WITH_ACTIVE_ADMIN, []],
    [
      'an invited Org Admin of an active org whose admins are all deactivated or invited',
      ADMIN_INVITED,
      'active',
      NO_ACTIVE_ADMIN,
      ['reinvite'],
    ],
    ['an invited Org Admin of an active org, empty user list', ADMIN_INVITED, 'active', [], ['reinvite']],
    ['an invited Org Admin of an active org that has an active Org Admin', ADMIN_INVITED, 'active', WITH_ACTIVE_ADMIN, []],
    [
      'an invited Org Admin, the only other user an active Org Admin',
      ADMIN_INVITED,
      'active',
      [ADMIN_INVITED, ADMIN_ACTIVE],
      [],
    ],
    ['an invited Org Admin of a deactivated org without an active Org Admin', ADMIN_INVITED, 'deactivated', NO_ACTIVE_ADMIN, []],
    ['an invited Org Admin of an org pending deletion', ADMIN_INVITED, 'pending_deletion', NO_ACTIVE_ADMIN, []],
    ['an invited editor of an active org without an active Org Admin', EDITOR_INVITED, 'active', NO_ACTIVE_ADMIN, []],
    ['an invited viewer of an active org without an active Org Admin', VIEWER_INVITED, 'active', NO_ACTIVE_ADMIN, []],
  ];

  it.each(ROWS)('%s -> %j', (_label, user, status, users, actions) => {
    expect(userActions(user, { status }, users)).toEqual(actions);
  });

  it.each(wrap(['deleted', 'pending', '', 'ACTIVE', '__proto__', 'constructor', null, undefined]))(
    'fails closed for the unknown user status %j',
    (status) => {
      const user = platformUser({ id: EDITOR_ACTIVE.id, status: status as PlatformUserStatus });

      expect(userActions(user, { status: 'active' }, NO_ACTIVE_ADMIN)).toEqual([]);
    },
  );

  it('an active editor whose org status is unknown is never offered a password reset', () => {
    expect(userActions(EDITOR_ACTIVE, { status: 'weird' as OrgStatus }, WITH_ACTIVE_ADMIN)).not.toContain(
      'resetPassword',
    );
  });
});

// --- Units -------------------------------------------------------------------------------

describe('bytesToGib / gibToBytes', () => {
  it.each([
    [0, 0],
    [GIB_BYTES, 1],
    [10 * GIB_BYTES, 10],
    [GIB_BYTES / 2, 0.5],
    [1_610_612_736, 1.5],
  ])('bytesToGib(%d) = %d', (bytes, gib) => {
    expect(bytesToGib(bytes)).toBe(gib);
  });

  it.each([
    [0, 0],
    [1, GIB_BYTES],
    [10, 10_737_418_240],
    [1.5, 1_610_612_736],
    [8_388_607, 9_007_198_180_999_168],
  ])('gibToBytes(%d) = %d', (gib, bytes) => {
    expect(gibToBytes(gib)).toBe(bytes);
  });

  it.each([1, 123_456_789, 1_610_612_736, 999_999_999_999])('round-trips %d bytes exactly', (bytes) => {
    expect(gibToBytes(bytesToGib(bytes))).toBe(bytes);
  });
});

describe('parseChf', () => {
  it.each([
    ['100', 10000],
    ['0', 0],
    ['12.5', 1250],
    ['12.50', 1250],
    [' 7 ', 700],
    ['007', 700],
    ['100.0', 10000],
    ['100.00', 10000],
    ['0.05', 5],
    ['0.5', 50],
    ['0.29', 29],
    ['0.57', 57],
    ['1.15', 115],
    ['4.35', 435],
    ['1234567890.99', 123456789099],
    ['9999999999.99', 999999999999],
    ['9999999999', 999999999900],
    ['0000000001', 100],
  ])('%j -> %d cents (exact, no float drift)', (value, cents) => {
    expect(parseChf(value)).toBe(cents);
  });

  it.each([
    '',
    '   ',
    '-1',
    '-0',
    '+1',
    '1e3',
    '1E3',
    '1.234',
    '0.001',
    'abc',
    '12345678901',
    '00000000001',
    '1,5',
    '.5',
    '5.',
    '1.2.3',
    "1'000",
    '1 000',
    '1_000',
    'CHF 10',
    '10 CHF',
    '10CHF',
    '0x10',
    'Infinity',
    'NaN',
    '١٢',
    '１２',
    '10\n5',
  ])('refuses %j', (value) => {
    expect(parseChf(value)).toBeNull();
  });
});

describe('toChfString', () => {
  it.each([
    [10000, '100.00'],
    [1250, '12.50'],
    [0, '0.00'],
    [29, '0.29'],
    [5, '0.05'],
    [50, '0.50'],
    [700, '7.00'],
    [123456789099, '1234567890.99'],
    [999999999999, '9999999999.99'],
  ])('%d cents -> %j', (cents, text) => {
    expect(toChfString(cents)).toBe(text);
  });

  it.each([0, 5, 29, 57, 115, 1250, 10000, 123456789099, 999999999999])(
    'parseChf(toChfString(%d)) gives the same cents back',
    (cents) => {
      expect(parseChf(toChfString(cents))).toBe(cents);
    },
  );
});

// --- Create form ---------------------------------------------------------------------------

const FIELD_ERROR_KEY: Record<OrgFormField, string> = {
  name: 'platform.orgs.form.error.name',
  email: 'platform.orgs.form.error.email',
  seats: 'platform.orgs.form.error.seats',
  budgetChf: 'platform.orgs.form.error.budget',
  storageGib: 'platform.orgs.form.error.storage',
};

function fieldError(field: OrgFormField, locale: CatalogLocale = 'en'): string {
  return catalogText(locale, FIELD_ERROR_KEY[field]);
}

describe('buildCreateOrgRequest', () => {
  const VALID: Readonly<OrgCreateInput> = Object.freeze({
    name: '  Muster AG  ',
    email: '  admin@muster.ch ',
    seats: 25,
    budgetChf: '250.5',
    storageGib: 20,
  });

  const VALID_BODY = {
    name: 'Muster AG',
    primary_admin_email: 'admin@muster.ch',
    seats: 25,
    monthly_budget_chf: '250.50',
    storage_quota: 20 * GIB_BYTES,
  };

  it('builds the exact five-key body: trimmed name and email, a two-decimal budget, storage in bytes', () => {
    expect(buildCreateOrgRequest(VALID)).toStrictEqual({ ok: true, value: VALID_BODY });
  });

  it('never sends a status (a new org always starts active)', () => {
    const result = buildCreateOrgRequest(VALID);

    expect(result.ok ? Object.keys(result.value).sort() : null).toEqual([
      'monthly_budget_chf',
      'name',
      'primary_admin_email',
      'seats',
      'storage_quota',
    ]);
  });

  it('the create defaults plus a name and an email make a valid request (10 seats, CHF 100.00, 10 GiB)', () => {
    expect(buildCreateOrgRequest({ ...CREATE_DEFAULTS, name: 'Muster AG', email: 'admin@muster.ch' })).toStrictEqual({
      ok: true,
      value: {
        name: 'Muster AG',
        primary_admin_email: 'admin@muster.ch',
        seats: 10,
        monthly_budget_chf: '100.00',
        storage_quota: 10 * GIB_BYTES,
      },
    });
  });

  const ACCEPTED: Array<[string, Partial<OrgCreateInput>, Record<string, unknown>]> = [
    ['a one-character name', { name: 'X' }, { name: 'X' }],
    ['a 120-character name', { name: 'n'.repeat(120) }, { name: 'n'.repeat(120) }],
    ['a padded name that is 120 characters once trimmed', { name: `  ${'n'.repeat(120)}  ` }, { name: 'n'.repeat(120) }],
    ['a name with accents and punctuation', { name: 'Zürcher Bäckerei & Co. (Genève)' }, { name: 'Zürcher Bäckerei & Co. (Genève)' }],
    ['a name with an emoji (a valid surrogate pair)', { name: '\u{1F3D4} Alpen AG' }, { name: '\u{1F3D4} Alpen AG' }],
    ['the minimum seats', { seats: 1 }, { seats: 1 }],
    ['the maximum seats', { seats: 100000 }, { seats: 100000 }],
    ['a zero budget', { budgetChf: '0' }, { monthly_budget_chf: '0.00' }],
    ['a padded budget', { budgetChf: ' 7 ' }, { monthly_budget_chf: '7.00' }],
    ['the largest budget', { budgetChf: '9999999999.99' }, { monthly_budget_chf: '9999999999.99' }],
    ['a zero storage quota', { storageGib: 0 }, { storage_quota: 0 }],
    ['the largest storage quota', { storageGib: 8388607 }, { storage_quota: 9_007_198_180_999_168 }],
  ];

  it.each(ACCEPTED)('accepts %s', (_label, override, bodyPart) => {
    expect(buildCreateOrgRequest({ ...VALID, ...override })).toStrictEqual({
      ok: true,
      value: { ...VALID_BODY, ...bodyPart },
    });
  });

  const REFUSED: Array<[OrgFormField, unknown]> = [
    ['name', ''],
    ['name', '   '],
    ['name', 'n'.repeat(121)],
    ['name', `  ${'n'.repeat(121)}  `],
    ['name', 'Muster\u0000AG'],
    ['name', 'Muster\u0007AG'],
    ['name', 'Muster\tAG'],
    ['name', 'Muster\nAG'],
    ['name', 'Muster\u0085AG'],
    ['name', 'Muster​AG'],
    ['name', 'Muster‍AG'],
    ['name', 'Muster‮AG'],
    ['name', 'Muster­AG'],
    ['name', 'Muster AG'],
    ['name', 'Muster AG'],
    ['name', 'Muster\ud800AG'],
    ['name', 'Muster\udc00AG'],
    ['email', ''],
    ['email', 'admin'],
    ['email', 'admin@muster'],
    ['email', '@muster.ch'],
    ['email', 'admin@@muster.ch'],
    ['email', 'ad min@muster.ch'],
    ['email', 'admin@muster.ch​'],
    ['seats', 0],
    ['seats', -1],
    ['seats', 100001],
    ['seats', 1.5],
    ['seats', Number.NaN],
    ['seats', Number.POSITIVE_INFINITY],
    ['seats', '10'],
    ['budgetChf', ''],
    ['budgetChf', '-1'],
    ['budgetChf', '1.234'],
    ['budgetChf', 'abc'],
    ['budgetChf', '1e3'],
    ['budgetChf', '12345678901'],
    ['budgetChf', '1,5'],
    ['storageGib', -1],
    ['storageGib', 0.5],
    ['storageGib', 10.5],
    ['storageGib', Number.NaN],
    ['storageGib', Number.POSITIVE_INFINITY],
    ['storageGib', 8388608],
    ['storageGib', '10'],
  ];

  it.each(REFUSED)('refuses %s = %j with only that field\'s message', (field, value) => {
    const input = { ...VALID, [field]: value } as OrgCreateInput;

    expect(buildCreateOrgRequest(input)).toStrictEqual({ ok: false, errors: { [field]: fieldError(field) } });
  });

  const ALL_BAD: OrgCreateInput = { name: '  ', email: 'nope', seats: 0, budgetChf: '-1', storageGib: -1 };

  it('reports every invalid field at once', () => {
    expect(buildCreateOrgRequest(ALL_BAD)).toStrictEqual({
      ok: false,
      errors: {
        name: fieldError('name'),
        email: fieldError('email'),
        seats: fieldError('seats'),
        budgetChf: fieldError('budgetChf'),
        storageGib: fieldError('storageGib'),
      },
    });
  });

  it.each(['de', 'fr'] as const)('translates the field messages into the active locale (%s)', (locale) => {
    setLocale(locale);

    expect(buildCreateOrgRequest(ALL_BAD)).toStrictEqual({
      ok: false,
      errors: {
        name: fieldError('name', locale),
        email: fieldError('email', locale),
        seats: fieldError('seats', locale),
        budgetChf: fieldError('budgetChf', locale),
        storageGib: fieldError('storageGib', locale),
      },
    });
  });
});

// --- Limits form -----------------------------------------------------------------------------

describe('limitsInputFrom', () => {
  it('copies the seats and the budget string and converts the quota to GiB', () => {
    expect(
      limitsInputFrom(org({ seats: 25, monthly_budget_chf: '250.50', storage_quota: 20 * GIB_BYTES })),
    ).toStrictEqual({ seats: 25, budgetChf: '250.50', storageGib: 20 });
  });

  it('keeps a quota that is not a whole number of GiB fractional', () => {
    expect(limitsInputFrom(org({ storage_quota: 1_610_612_736 })).storageGib).toBe(1.5);
  });
});

describe('buildLimitsPatch', () => {
  const STORED = Object.freeze(org({ seats: 10, monthly_budget_chf: '100.00', storage_quota: 10 * GIB_BYTES }));

  function input(overrides: Partial<OrgLimitsInput> = {}): OrgLimitsInput {
    return { seats: 10, budgetChf: '100.00', storageGib: 10, ...overrides };
  }

  it('the unchanged form (limitsInputFrom) is ok with nothing to send', () => {
    expect(buildLimitsPatch(STORED, limitsInputFrom(STORED))).toStrictEqual({ ok: true, value: null });
  });

  it.each(['100', '100.0', ' 100 ', '0100', '100.00'])(
    'a budget of %j equals the stored "100.00" by value: nothing to send',
    (budgetChf) => {
      expect(buildLimitsPatch(STORED, input({ budgetChf }))).toStrictEqual({ ok: true, value: null });
    },
  );

  it('a stored budget of "100" equals an input of "100.00": nothing to send', () => {
    expect(buildLimitsPatch(org({ monthly_budget_chf: '100' }), input({ budgetChf: '100.00' }))).toStrictEqual({
      ok: true,
      value: null,
    });
  });

  const CHANGES: Array<[string, Partial<OrgLimitsInput>, Record<string, unknown>]> = [
    ['only the seats', { seats: 12 }, { seats: 12 }],
    ['the seats down to the minimum', { seats: 1 }, { seats: 1 }],
    ['only the budget', { budgetChf: '250.5' }, { monthly_budget_chf: '250.50' }],
    ['the budget down to zero', { budgetChf: '0' }, { monthly_budget_chf: '0.00' }],
    ['only the storage', { storageGib: 25 }, { storage_quota: 25 * GIB_BYTES }],
    ['the storage down to zero', { storageGib: 0 }, { storage_quota: 0 }],
    [
      'all three limits',
      { seats: 12, budgetChf: '250.5', storageGib: 25 },
      { seats: 12, monthly_budget_chf: '250.50', storage_quota: 25 * GIB_BYTES },
    ],
  ];

  it.each(CHANGES)('sends %s, nothing else', (_label, overrides, patch) => {
    expect(buildLimitsPatch(STORED, input(overrides))).toStrictEqual({ ok: true, value: patch });
  });

  it.each([1_610_612_736, 123_456_789])(
    'a stored quota of %d bytes (not whole GiB) left unchanged is neither validated nor sent',
    (storage_quota) => {
      const stored = org({ storage_quota });

      expect([
        buildLimitsPatch(stored, limitsInputFrom(stored)),
        buildLimitsPatch(stored, { ...limitsInputFrom(stored), seats: 12 }),
      ]).toStrictEqual([
        { ok: true, value: null },
        { ok: true, value: { seats: 12 } },
      ]);
    },
  );

  const REFUSED: Array<[OrgFormField, Partial<OrgLimitsInput>]> = [
    ['seats', { seats: 0 }],
    ['seats', { seats: 100001 }],
    ['seats', { seats: 1.5 }],
    ['seats', { seats: Number.NaN }],
    ['budgetChf', { budgetChf: 'abc' }],
    ['budgetChf', { budgetChf: '' }],
    ['budgetChf', { budgetChf: '-1' }],
    ['budgetChf', { budgetChf: '100.001' }],
    ['budgetChf', { budgetChf: '1e3' }],
    ['storageGib', { storageGib: -1 }],
    ['storageGib', { storageGib: 10.5 }],
    ['storageGib', { storageGib: 8388608 }],
    ['storageGib', { storageGib: Number.NaN }],
  ];

  it.each(REFUSED)('a changed, invalid %s (%j) is that field\'s create-form error, nothing sent', (field, overrides) => {
    expect(buildLimitsPatch(STORED, input(overrides))).toStrictEqual({
      ok: false,
      errors: { [field]: fieldError(field) },
    });
  });

  it('reports every changed invalid field at once', () => {
    expect(buildLimitsPatch(STORED, input({ seats: 0, budgetChf: 'x', storageGib: -1 }))).toStrictEqual({
      ok: false,
      errors: {
        seats: fieldError('seats'),
        budgetChf: fieldError('budgetChf'),
        storageGib: fieldError('storageGib'),
      },
    });
  });

  it('translates the field messages into the active locale (de)', () => {
    setLocale('de');

    expect(buildLimitsPatch(STORED, input({ seats: 0 }))).toStrictEqual({
      ok: false,
      errors: { seats: fieldError('seats', 'de') },
    });
  });
});

// --- Error messages ----------------------------------------------------------------------------

describe('platformErrorMessage', () => {
  const ROWS: Array<[string, () => unknown, Subject | undefined, string]> = [
    ['409 email_taken', () => apiError(409, 'email_taken'), undefined, 'platform.error.emailTaken'],
    ['409 email_taken for a user', () => apiError(409, 'email_taken'), 'user', 'platform.error.emailTaken'],
    ['409 seat_limit', () => apiError(409, 'seat_limit'), 'user', 'platform.error.seatLimit'],
    ['409 invalid_status (default subject)', () => apiError(409, 'invalid_status'), undefined, 'platform.error.orgInvalidStatus'],
    ['409 invalid_status for an org', () => apiError(409, 'invalid_status'), 'org', 'platform.error.orgInvalidStatus'],
    ['409 invalid_status for a user', () => apiError(409, 'invalid_status'), 'user', 'platform.error.userInvalidStatus'],
    ['409 invalid_status for settings', () => apiError(409, 'invalid_status'), 'settings', 'platform.error.orgInvalidStatus'],
    ['409 last_admin', () => apiError(409, 'last_admin'), 'user', 'platform.error.lastAdmin'],
    ['409 has_active_admin', () => apiError(409, 'has_active_admin'), 'user', 'platform.error.hasActiveAdmin'],
    [
      '409 residency_confirmation',
      () => apiError(409, 'residency_confirmation'),
      'settings',
      'platform.error.residencyConfirmation',
    ],
    ['404 (default subject)', () => apiError(404), undefined, 'platform.error.orgNotFound'],
    ['404 for an org', () => apiError(404), 'org', 'platform.error.orgNotFound'],
    ['404 for a user', () => apiError(404), 'user', 'platform.error.userNotFound'],
    ['404 for settings', () => apiError(404), 'settings', 'platform.error.generic'],
    ['400', () => apiError(400), undefined, 'platform.error.invalidInput'],
    ['400 for settings', () => apiError(400), 'settings', 'platform.error.invalidInput'],
    ['422', () => apiError(422), undefined, 'platform.error.invalidInput'],
    ['422 for a user', () => apiError(422), 'user', 'platform.error.invalidInput'],
    ['422 for settings', () => apiError(422), 'settings', 'platform.error.invalidInput'],
    ['422 with an unknown reason', () => apiError(422, 'too_short'), undefined, 'platform.error.invalidInput'],
    ['429', () => apiError(429), undefined, 'platform.error.rateLimited'],
    ['429 for settings', () => apiError(429), 'settings', 'platform.error.rateLimited'],
    ['403', () => apiError(403), undefined, 'platform.error.forbidden'],
    ['403 for a user', () => apiError(403), 'user', 'platform.error.forbidden'],
    ['409 without a reason', () => apiError(409), undefined, 'platform.error.generic'],
    ['409 with an unknown reason', () => apiError(409, 'something_else'), 'user', 'platform.error.generic'],
    ['500', () => apiError(500), undefined, 'platform.error.generic'],
    ['502 for settings', () => apiError(502), 'settings', 'platform.error.generic'],
    ['401', () => apiError(401), undefined, 'platform.error.generic'],
    ['418', () => apiError(418), 'user', 'platform.error.generic'],
  ];

  it.each(ROWS)('%s -> its catalog message', (_label, make, subject, key) => {
    expect(platformErrorMessage(make(), subject)).toBe(catalogText('en', key));
  });

  it.each([
    ['email_taken on a 422', apiError(422, 'email_taken'), 'platform.error.emailTaken'],
    ['seat_limit on a 429', apiError(429, 'seat_limit'), 'platform.error.seatLimit'],
    ['last_admin on a 403', apiError(403, 'last_admin'), 'platform.error.lastAdmin'],
    ['has_active_admin on a 404', apiError(404, 'has_active_admin'), 'platform.error.hasActiveAdmin'],
    ['residency_confirmation on a 400', apiError(400, 'residency_confirmation'), 'platform.error.residencyConfirmation'],
  ])('a reason beats the status (%s)', (_label, error, key) => {
    expect(platformErrorMessage(error, 'user')).toBe(catalogText('en', key));
  });

  const NON_API_ERRORS: Array<[string, unknown]> = [
    ['a plain Error', new Error(SECRET_DETAIL)],
    ['a network TypeError', new TypeError(`Failed to fetch ${SECRET_DETAIL}`)],
    ['an Error carrying a status and a reason', Object.assign(new Error(SECRET_DETAIL), { status: 404, reason: 'email_taken' })],
    ['an ApiError-shaped plain object', { status: 409, reason: 'last_admin', message: SECRET_DETAIL, detail: SECRET_DETAIL }],
    ['the invalid-id Error of the API client', new Error('Invalid id')],
    ['a string', SECRET_DETAIL],
    ['undefined', undefined],
    ['null', null],
    ['a number', 404],
  ];

  it.each(NON_API_ERRORS)('%s -> the generic message', (_label, error) => {
    expect(platformErrorMessage(error)).toBe(catalogText('en', 'platform.error.generic'));
  });

  it.each(['user', 'settings'] as const)('a non-ApiError is the generic message for the %s subject too', (subject) => {
    expect(platformErrorMessage(new Error(SECRET_DETAIL), subject)).toBe(catalogText('en', 'platform.error.generic'));
  });

  it('never returns the backend detail, the status text or the error message, whatever the error', () => {
    const inputs: unknown[] = [
      ...ROWS.map(([, make]) => make()),
      apiError(409, 'email_taken', SECRET_DETAIL),
      new ApiError(500, 'SECRET status text'),
      new ApiError(404, 'SECRET status text', undefined, 'unknown_reason'),
      ...NON_API_ERRORS.map(([, error]) => error),
    ];
    const subjects: Subject[] = ['org', 'user', 'settings'];

    const leaks = inputs
      .flatMap((error) => subjects.map((subject) => platformErrorMessage(error, subject)))
      .filter((text) => text.includes('SECRET') || text.includes('<script>') || text.includes('Invalid id'));

    expect(leaks).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('translates into the active locale (%s)', (locale) => {
    setLocale(locale);

    expect([
      platformErrorMessage(apiError(409, 'invalid_status'), 'user'),
      platformErrorMessage(apiError(404), 'org'),
      platformErrorMessage(apiError(422), 'settings'),
      platformErrorMessage(undefined),
    ]).toEqual([
      catalogText(locale, 'platform.error.userInvalidStatus'),
      catalogText(locale, 'platform.error.orgNotFound'),
      catalogText(locale, 'platform.error.invalidInput'),
      catalogText(locale, 'platform.error.generic'),
    ]);
  });
});

// --- Confirm copy ---------------------------------------------------------------------------------

function expectedCopy(
  locale: CatalogLocale,
  base: string,
  name: string,
  destructive: boolean,
): ConfirmCopy {
  return {
    heading: catalogText(locale, `${base}.heading`, { name }),
    subtext: catalogText(locale, `${base}.subtext`, { name }),
    confirmLabel: catalogText(locale, `${base}.confirm`, { name }),
    destructive,
  };
}

/** A name that would re-expand a placeholder, act as a `$&` pattern or carry markup if handled carelessly. */
const HOSTILE_NAME = '{name} $& $1 <b>x</b>';

describe('orgConfirmCopy', () => {
  const KINDS: readonly OrgConfirmKind[] = [
    'deactivate',
    'reactivate',
    'scheduleDeletion',
    'cancelDeletion',
    'residencyOn',
    'residencyOff',
  ];

  const DESTRUCTIVE: Record<OrgConfirmKind, boolean> = {
    deactivate: true,
    reactivate: false,
    scheduleDeletion: true,
    cancelDeletion: false,
    residencyOn: false,
    residencyOff: true,
  };

  const CASES = LOCALES.flatMap((locale) => KINDS.map((kind): [CatalogLocale, OrgConfirmKind] => [locale, kind]));

  it.each(CASES)('%s %s: the platform.orgs.confirm.* copy with the org name substituted', (locale, kind) => {
    setLocale(locale);

    expect(orgConfirmCopy(kind, 'Muster AG')).toEqual(
      expectedCopy(locale, `platform.orgs.confirm.${kind}`, 'Muster AG', DESTRUCTIVE[kind]),
    );
  });

  it.each(KINDS)('%s: the heading names the org', (kind) => {
    expect(orgConfirmCopy(kind, 'Muster AG').heading).toContain('Muster AG');
  });

  it.each(KINDS)('%s: no placeholder is left unfilled', (kind) => {
    const copy = orgConfirmCopy(kind, 'Muster AG');

    expect([copy.heading, copy.subtext, copy.confirmLabel].filter((text) => /\{[A-Za-z_]/.test(text))).toEqual([]);
  });

  it('destructive is true exactly for deactivate, scheduleDeletion and residencyOff', () => {
    expect(KINDS.filter((kind) => orgConfirmCopy(kind, 'Muster AG').destructive)).toEqual([
      'deactivate',
      'scheduleDeletion',
      'residencyOff',
    ]);
  });

  it.each(KINDS)('%s: inserts a hostile org name literally (no placeholder or $-pattern expansion)', (kind) => {
    const copy = orgConfirmCopy(kind, HOSTILE_NAME);

    expect({ copy, verbatim: copy.heading.includes(HOSTILE_NAME) }).toEqual({
      copy: expectedCopy('en', `platform.orgs.confirm.${kind}`, HOSTILE_NAME, DESTRUCTIVE[kind]),
      verbatim: true,
    });
  });
});

describe('userConfirmCopy', () => {
  const KINDS: readonly UserConfirmKind[] = ['deactivate', 'reactivate', 'resetPassword'];

  const DESTRUCTIVE: Record<UserConfirmKind, boolean> = {
    deactivate: true,
    reactivate: false,
    resetPassword: false,
  };

  const CASES = LOCALES.flatMap((locale) => KINDS.map((kind): [CatalogLocale, UserConfirmKind] => [locale, kind]));

  it.each(CASES)('%s %s: the platform.users.confirm.* copy with the subject substituted', (locale, kind) => {
    setLocale(locale);

    expect(userConfirmCopy(kind, 'Alice Muster')).toEqual(
      expectedCopy(locale, `platform.users.confirm.${kind}`, 'Alice Muster', DESTRUCTIVE[kind]),
    );
  });

  it.each(KINDS)('%s: the heading names the subject', (kind) => {
    expect(userConfirmCopy(kind, 'alice@muster.ch').heading).toContain('alice@muster.ch');
  });

  it.each(KINDS)('%s: no placeholder is left unfilled', (kind) => {
    const copy = userConfirmCopy(kind, 'Alice Muster');

    expect([copy.heading, copy.subtext, copy.confirmLabel].filter((text) => /\{[A-Za-z_]/.test(text))).toEqual([]);
  });

  it('destructive is true for deactivate only', () => {
    expect(KINDS.filter((kind) => userConfirmCopy(kind, 'Alice Muster').destructive)).toEqual(['deactivate']);
  });

  it.each(KINDS)('%s: inserts a hostile subject literally (no placeholder or $-pattern expansion)', (kind) => {
    const copy = userConfirmCopy(kind, HOSTILE_NAME);

    expect({ copy, verbatim: copy.heading.includes(HOSTILE_NAME) }).toEqual({
      copy: expectedCopy('en', `platform.users.confirm.${kind}`, HOSTILE_NAME, DESTRUCTIVE[kind]),
      verbatim: true,
    });
  });
});

// --- No content in logs ------------------------------------------------------------------------------

describe('platform org services logging', () => {
  it('never writes to the console (no names, emails or error details in logs)', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    platformTabFrom('defaults');
    orgIdFrom('../x');
    orgActions({ status: 'weird' as OrgStatus });
    userActions(ADMIN_INVITED, { status: 'active' }, NO_ACTIVE_ADMIN);
    parseChf('abc');
    toChfString(1250);
    buildCreateOrgRequest({ name: 'Muster\u0000AG', email: 'nope', seats: 0, budgetChf: 'x', storageGib: -1 });
    buildCreateOrgRequest({ name: 'Muster AG', email: 'admin@muster.ch', seats: 10, budgetChf: '100', storageGib: 10 });
    buildLimitsPatch(org(), { seats: 0, budgetChf: 'x', storageGib: 1.5 });
    limitsInputFrom(org());
    platformErrorMessage(apiError(409, 'email_taken'));
    platformErrorMessage(new Error(SECRET_DETAIL), 'user');
    orgConfirmCopy('scheduleDeletion', 'Muster AG');
    userConfirmCopy('resetPassword', 'alice@muster.ch');

    expect(spies.map((spy) => spy.mock.calls.length)).toEqual([0, 0, 0, 0, 0]);
  });
});
