/**
 * Org users pure services tests (issue #165: Organization console, users and
 * invitations UI).
 *
 * `@/services/orgUsers` holds the logic the Users tab and its store use, so
 * it can be tested without mounting anything:
 * - `ASSIGNABLE_ROLES` is exactly Org Admin and Editor: Viewer is NOT offered
 *   in the invite and role-change UI in V1 (the API and access.py keep the
 *   role). `isAssignableRole` accepts only those two (prototype keys,
 *   'super_admin', non-strings → false). `ROLE_LABEL_KEYS` maps every member
 *   role to the existing `auth.role.*` catalog keys.
 * - `STATUS_FILTERS` / `isStatusFilter`, `filterUsers` / `filterInvitations`:
 *   status semantics ('all' every user status, 'invited' only invitations,
 *   'active' / 'deactivated' only those users), and a trimmed,
 *   case-insensitive, LITERAL substring search on the user's name (null → no
 *   name match) or email; an invitation matches on its email only. Input
 *   order is kept and the input arrays are never mutated.
 * - `seatLabel` ("7 / 10 seats" in en, through the active catalog; null →
 *   null), `seatsFull` (no free seat), `displayName` (trimmed name, else the
 *   email).
 * - `isPlausibleEmail`: the client-side mirror of the backend's invite email
 *   rule (trimmed, 3 to 254 chars, no whitespace / control / zero-width
 *   characters inside, exactly one '@' after a non-empty local part, a '.'
 *   inside the domain that is neither its first nor its last character).
 * - `buildProfilePatch`: only the changed fields (trimmed); an empty name is
 *   never a change; a capitalization change of the email IS a change; null
 *   when nothing changed.
 * - `orgUserErrorMessage`: a translated catalog message per the #165 mapping
 *   (reason beats status; 404 depends on the subject). It NEVER returns the
 *   backend's `detail` / the error's message (#139 §5: error responses are
 *   never echoed).
 * - `orgTabFrom`: the `?tab=` query value → 'permissions' only for exactly
 *   'permissions', else 'users'. Issue #169 adds the Settings tab: 'settings'
 *   (exactly that string) → 'settings'; case, whitespace or array variants
 *   still fall back to 'users'.
 * - `confirmCopy`: the confirm sheet copy per pending action (catalog keys,
 *   `{name}` / `{role}` substituted, destructive flags, the self-warning
 *   appended for deactivate / delete / role on your own account).
 *
 * Expected strings are read from the real en/de/fr catalogs and interpolated
 * here, never hard-coded (except the contract's fixed en seat label). No
 * component is mounted.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import type { MemberRole, OrgInvitation, OrgSeats, OrgUser } from '@/api/types';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import {
  ASSIGNABLE_ROLES,
  ROLE_LABEL_KEYS,
  STATUS_FILTERS,
  buildProfilePatch,
  confirmCopy,
  displayName,
  filterInvitations,
  filterUsers,
  isAssignableRole,
  isPlausibleEmail,
  isStatusFilter,
  orgTabFrom,
  orgUserErrorMessage,
  seatLabel,
  seatsFull,
  type DirectoryFilter,
  type OrgTab,
  type PendingKind,
  type StatusFilter,
} from '@/services/orgUsers';

type CatalogLocale = 'en' | 'de' | 'fr';

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

// --- Fixtures -------------------------------------------------------------------

function user(overrides: Partial<OrgUser> & Pick<OrgUser, 'id' | 'email'>): OrgUser {
  return {
    name: null,
    role: 'editor',
    status: 'active',
    created_at: '2026-09-01T08:00:00Z',
    last_login_at: null,
    ...overrides,
  };
}

const ALICE = user({
  id: '0b9f6c1e-3a52-4c1d-9a8e-5f2d7c3b1a90',
  name: 'Alice Muster',
  email: 'alice@example.ch',
  role: 'org_admin',
  status: 'active',
  last_login_at: '2026-10-01T07:30:00Z',
});
const BRUNO = user({
  id: '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
  name: 'Bruno Keller',
  email: 'bruno.keller@firma.ch',
  role: 'editor',
  status: 'deactivated',
});
const CARLA = user({
  id: '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a',
  name: null,
  email: 'carla@example.ch',
  role: 'viewer',
  status: 'active',
});
const DORA = user({
  id: '3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b',
  name: 'Dora (Ops) [lead]',
  email: 'dora@firma.ch',
  role: 'editor',
  status: 'active',
});
const EMILE = user({
  id: '4f5a6b7c-8d9e-4f0a-9b2c-3d4e5f6a7b8c',
  name: 'Émile Zürcher',
  email: 'emile@zuerich.ch',
  role: 'editor',
  status: 'deactivated',
});

const USERS: readonly OrgUser[] = [ALICE, BRUNO, CARLA, DORA, EMILE];

function invitation(overrides: Partial<OrgInvitation> & Pick<OrgInvitation, 'id' | 'email'>): OrgInvitation {
  return {
    role: 'editor',
    sent_at: '2026-10-02T09:00:00Z',
    expires_at: '2026-10-09T09:00:00Z',
    expired: false,
    ...overrides,
  };
}

const INV_ERIK = invitation({ id: '5a1c9e2d-7b3f-4d8a-9c6e-1f0b2a3d4e5f', email: 'erik@example.ch' });
const INV_FABIENNE = invitation({
  id: '6b2d0f3e-8c4a-4e9b-8d7f-2a1c3b4d5e6f',
  email: 'Fabienne.Roth@Firma.ch',
  role: 'org_admin',
  expired: true,
});
const INV_GIAN = invitation({ id: '7c3e1a4f-9d5b-4fac-9e8a-3b2d4c5e6f7a', email: 'gian(ops)@example.ch' });

const INVITATIONS: readonly OrgInvitation[] = [INV_ERIK, INV_FABIENNE, INV_GIAN];

function f(query: string, status: StatusFilter = 'all'): DirectoryFilter {
  return { query, status };
}

function ids(items: ReadonlyArray<{ id: string }>): string[] {
  return items.map((item) => item.id);
}

function frozenCopy<T extends object>(items: readonly T[]): readonly T[] {
  return Object.freeze(items.map((item) => Object.freeze({ ...item }) as T));
}

// --- Roles ------------------------------------------------------------------------

describe('ASSIGNABLE_ROLES / isAssignableRole', () => {
  it('offers exactly Org Admin and Editor, never Viewer', () => {
    expect([...ASSIGNABLE_ROLES]).toEqual(['org_admin', 'editor']);
  });

  it.each(['org_admin', 'editor'])('accepts %s', (role) => {
    expect(isAssignableRole(role)).toBe(true);
  });

  // Each case is wrapped in its own tuple: it.each would spread a bare array case.
  it.each(
    (
      [
        'viewer',
        'super_admin',
        '__proto__',
        'constructor',
        'toString',
        'hasOwnProperty',
        'ORG_ADMIN',
        ' editor',
        '',
        1,
        null,
        undefined,
        {},
        ['editor'],
      ] as unknown[]
    ).map((value): [unknown] => [value]),
  )('refuses %j', (role) => {
    expect(isAssignableRole(role)).toBe(false);
  });

  it('maps every member role to the existing auth.role.* label keys', () => {
    expect({ ...ROLE_LABEL_KEYS }).toStrictEqual({
      org_admin: 'auth.role.orgAdmin',
      editor: 'auth.role.editor',
      viewer: 'auth.role.viewer',
    });
  });
});

// --- Status filters ----------------------------------------------------------------

describe('STATUS_FILTERS / isStatusFilter', () => {
  it('lists all, active, deactivated, invited in that order', () => {
    expect([...STATUS_FILTERS]).toEqual(['all', 'active', 'deactivated', 'invited']);
  });

  it.each(['all', 'active', 'deactivated', 'invited'])('accepts %s', (value) => {
    expect(isStatusFilter(value)).toBe(true);
  });

  it.each(
    (['expired', 'ALL', 'Active', '', ' all', '__proto__', 'constructor', null, undefined, 1, ['all'], {}] as unknown[]).map(
      (value): [unknown] => [value],
    ),
  )(
    'refuses %j',
    (value) => {
      expect(isStatusFilter(value)).toBe(false);
    },
  );
});

describe('filterUsers', () => {
  it("'all' with an empty query returns every user in input order", () => {
    expect(ids(filterUsers(USERS, f('')))).toEqual(ids(USERS));
  });

  it("'active' keeps only active users", () => {
    expect(ids(filterUsers(USERS, f('', 'active')))).toEqual(ids([ALICE, CARLA, DORA]));
  });

  it("'deactivated' keeps only deactivated users", () => {
    expect(ids(filterUsers(USERS, f('', 'deactivated')))).toEqual(ids([BRUNO, EMILE]));
  });

  it("'invited' returns no users (even when the query matches)", () => {
    expect([filterUsers(USERS, f('', 'invited')), filterUsers(USERS, f('alice', 'invited'))]).toEqual([[], []]);
  });

  it('a whitespace-only query matches everything for the status', () => {
    expect(ids(filterUsers(USERS, f('   ', 'deactivated')))).toEqual(ids([BRUNO, EMILE]));
  });

  it('trims the query and matches the name case-insensitively', () => {
    expect(ids(filterUsers(USERS, f('  ALICE  ')))).toEqual(ids([ALICE]));
  });

  it('matches a name substring', () => {
    expect(ids(filterUsers(USERS, f('kell')))).toEqual(ids([BRUNO]));
  });

  it('matches non-ASCII names case-insensitively', () => {
    expect(ids(filterUsers(USERS, f('ÉMILE')))).toEqual(ids([EMILE]));
  });

  it('matches an email substring case-insensitively', () => {
    expect(ids(filterUsers(USERS, f('FIRMA.CH')))).toEqual(ids([BRUNO, DORA]));
  });

  it('combines the query with the status', () => {
    expect([
      ids(filterUsers(USERS, f('firma', 'active'))),
      ids(filterUsers(USERS, f('firma', 'deactivated'))),
      ids(filterUsers(USERS, f('example.ch', 'active'))),
    ]).toEqual([ids([DORA]), ids([BRUNO]), ids([ALICE, CARLA])]);
  });

  it('matches a user without a name on the email only', () => {
    expect(ids(filterUsers(USERS, f('carla')))).toEqual(ids([CARLA]));
  });

  it('never matches a null name as the text "null"', () => {
    expect(filterUsers(USERS, f('null'))).toEqual([]);
  });

  it('never searches the role, the status or the id', () => {
    expect([
      filterUsers(USERS, f('org_admin')),
      filterUsers(USERS, f('viewer')),
      filterUsers(USERS, f('deactivated')),
      filterUsers(USERS, f('0b9f6c1e')),
    ]).toEqual([[], [], [], []]);
  });

  it.each([
    ['.*', [] as OrgUser[]],
    ['^alice', [] as OrgUser[]],
    ['alice@example.ch$', [] as OrgUser[]],
    ['a+', [] as OrgUser[]],
    ['(', [DORA]],
    ['[', [DORA]],
    ['(ops)', [DORA]],
  ])('matches the regex-like query %j literally', (query, expected) => {
    expect(ids(filterUsers(USERS, f(query)))).toEqual(ids(expected));
  });

  it('keeps the input order', () => {
    const reversed = [...USERS].reverse();

    expect(ids(filterUsers(reversed, f('example.ch')))).toEqual(ids([CARLA, ALICE]));
  });

  it('never mutates the input array or its users', () => {
    const input = frozenCopy(USERS);
    const before = structuredClone([...input]);

    const results = [
      filterUsers(input, f('firma')),
      filterUsers(input, f('', 'deactivated')),
      filterUsers(input, f('')),
    ];

    expect({ input: [...input], resultIds: results.map(ids) }).toEqual({
      input: before,
      resultIds: [ids([BRUNO, DORA]), ids([BRUNO, EMILE]), ids(USERS)],
    });
  });
});

describe('filterInvitations', () => {
  it("'all' and 'invited' with an empty query return every invitation (expired included) in input order", () => {
    expect([ids(filterInvitations(INVITATIONS, f(''))), ids(filterInvitations(INVITATIONS, f('', 'invited')))]).toEqual([
      ids(INVITATIONS),
      ids(INVITATIONS),
    ]);
  });

  it("'active' and 'deactivated' return no invitations (even when the query matches)", () => {
    expect([
      filterInvitations(INVITATIONS, f('', 'active')),
      filterInvitations(INVITATIONS, f('erik', 'active')),
      filterInvitations(INVITATIONS, f('', 'deactivated')),
      filterInvitations(INVITATIONS, f('erik', 'deactivated')),
    ]).toEqual([[], [], [], []]);
  });

  it('trims the query and matches the email case-insensitively', () => {
    expect([
      ids(filterInvitations(INVITATIONS, f('  FIRMA  '))),
      ids(filterInvitations(INVITATIONS, f('fabienne.roth', 'invited'))),
    ]).toEqual([ids([INV_FABIENNE]), ids([INV_FABIENNE])]);
  });

  it('matches on the email only (never the role, the id or the expiry)', () => {
    expect([
      filterInvitations(INVITATIONS, f('org_admin')),
      filterInvitations(INVITATIONS, f('editor')),
      filterInvitations(INVITATIONS, f('5a1c9e2d')),
      filterInvitations(INVITATIONS, f('expired')),
      filterInvitations(INVITATIONS, f('2026')),
    ]).toEqual([[], [], [], [], []]);
  });

  it.each([
    ['.*', [] as OrgInvitation[]],
    ['^erik', [] as OrgInvitation[]],
    ['(', [INV_GIAN]],
    ['(ops)', [INV_GIAN]],
  ])('matches the regex-like query %j literally', (query, expected) => {
    expect(ids(filterInvitations(INVITATIONS, f(query)))).toEqual(ids(expected));
  });

  it('keeps the input order and never mutates the input', () => {
    const input = frozenCopy([...INVITATIONS].reverse());
    const before = structuredClone([...input]);

    const result = filterInvitations(input, f('example.ch'));

    expect({ result: ids(result), input: [...input] }).toEqual({
      result: ids([INV_GIAN, INV_ERIK]),
      input: before,
    });
  });
});

// --- Seats and display ----------------------------------------------------------

describe('seatLabel', () => {
  it('reads "7 / 10 seats" in en', () => {
    expect(seatLabel({ used: 7, limit: 10 })).toBe('7 / 10 seats');
  });

  it('uses the en catalog text with the numbers', () => {
    expect(seatLabel({ used: 0, limit: 3 })).toBe(catalogText('en', 'orgUsers.seats', { used: 0, limit: 3 }));
  });

  it.each(['de', 'fr'] as const)('uses the %s catalog text with the numbers', (locale) => {
    setLocale(locale);

    const label = seatLabel({ used: 7, limit: 10 });

    expect({ label, hasNumbers: /7/.test(label ?? '') && /10/.test(label ?? '') }).toEqual({
      label: catalogText(locale, 'orgUsers.seats', { used: 7, limit: 10 }),
      hasNumbers: true,
    });
  });

  it('returns null when the seat usage is unknown', () => {
    expect(seatLabel(null)).toBeNull();
  });
});

describe('seatsFull', () => {
  it.each([
    [{ used: 7, limit: 10 }, false],
    [{ used: 9, limit: 10 }, false],
    [{ used: 10, limit: 10 }, true],
    [{ used: 11, limit: 10 }, true],
    [{ used: 0, limit: 0 }, true],
    [{ used: 0, limit: 1 }, false],
  ] as Array<[OrgSeats, boolean]>)('%j → %s', (seats, full) => {
    expect(seatsFull(seats)).toBe(full);
  });

  it('is false when the seat usage is unknown', () => {
    expect(seatsFull(null)).toBe(false);
  });
});

describe('displayName', () => {
  it.each([
    [{ name: 'Alice Muster', email: 'alice@example.ch' }, 'Alice Muster'],
    [{ name: '  Alice Muster  ', email: 'alice@example.ch' }, 'Alice Muster'],
    [{ name: null, email: 'carla@example.ch' }, 'carla@example.ch'],
    [{ name: '', email: 'carla@example.ch' }, 'carla@example.ch'],
    [{ name: '   ', email: 'carla@example.ch' }, 'carla@example.ch'],
  ] as Array<[Pick<OrgUser, 'name' | 'email'>, string]>)('%j → %j', (input, expected) => {
    expect(displayName(input)).toBe(expected);
  });
});

// --- Email plausibility -----------------------------------------------------------

describe('isPlausibleEmail', () => {
  const LOCAL_64 = 'a'.repeat(64);
  // 64 + 1 + 189 = 254 characters; the domain labels stay short.
  const DOMAIN_189 = `${'c'.repeat(62)}.${'d'.repeat(61)}.${'e'.repeat(61)}.ch`;
  const EMAIL_254 = `${LOCAL_64}@${DOMAIN_189}`;
  const EMAIL_255 = `${LOCAL_64}@c${DOMAIN_189}`;

  const ch = (code: number): string => String.fromCharCode(code);

  it('test setup: the boundary addresses have 254 and 255 characters', () => {
    expect([EMAIL_254.length, EMAIL_255.length]).toEqual([254, 255]);
  });

  it.each([
    ['a plain address', 'alice@example.ch'],
    ['the shortest shape', 'a@b.c'],
    ['dots, plus and subdomains', 'first.last+tag@sub.example.co.uk'],
    ['non-ASCII letters', 'zoë@exämple.ch'],
    ['capital letters', 'Alice@Example.CH'],
    ['surrounding whitespace (trimmed)', '  alice@example.ch  '],
    ['a trailing newline (trimmed)', 'alice@example.ch\n'],
    ['254 characters', EMAIL_254],
    ['254 characters after trimming', `  ${EMAIL_254}  `],
  ])('accepts %s', (_label, value) => {
    expect(isPlausibleEmail(value)).toBe(true);
  });

  it.each([
    ['an empty string', ''],
    ['only whitespace', '   '],
    ['no @', 'alice.example.ch'],
    ['two @', 'alice@@example.ch'],
    ['two separate @', 'al@ice@example.ch'],
    ['no local part', '@example.ch'],
    ['no domain', 'alice@'],
    ['a domain without a dot', 'alice@example'],
    ["a domain whose only '.' is first", 'alice@.ch'],
    ["a domain whose only '.' is last", 'alice@example.'],
    ['a domain that is only a dot', 'alice@.'],
    ['a space inside', 'ali ce@example.ch'],
    ['a space in the domain', 'alice@exa mple.ch'],
    ['a tab inside', 'alice\t@example.ch'],
    ['a newline inside', 'alice\n@example.ch'],
    ['a no-break space inside', `alice${ch(0xa0)}@example.ch`],
    ['a zero-width space inside', `ali${ch(0x200b)}ce@example.ch`],
    ['a zero-width joiner inside', `ali${ch(0x200d)}ce@example.ch`],
    ['a right-to-left override inside', `ali${ch(0x202e)}ce@example.ch`],
    ['a byte-order mark inside', `ali${ch(0xfeff)}ce@example.ch`],
    ['a NUL inside', `ali${ch(0x0)}ce@example.ch`],
    ['a BEL control character inside', `ali${ch(0x7)}ce@example.ch`],
    ['a DEL control character inside', `ali${ch(0x7f)}ce@example.ch`],
    ['a line separator inside', `ali${ch(0x2028)}ce@example.ch`],
    ['255 characters', EMAIL_255],
  ])('refuses %s', (_label, value) => {
    expect(isPlausibleEmail(value)).toBe(false);
  });
});

// --- Profile patch ------------------------------------------------------------------

describe('buildProfilePatch', () => {
  it('returns null when nothing changed', () => {
    expect(buildProfilePatch(ALICE, { name: 'Alice Muster', email: 'alice@example.ch' })).toBeNull();
  });

  it('returns null when only surrounding whitespace differs', () => {
    expect(buildProfilePatch(ALICE, { name: '  Alice Muster ', email: ' alice@example.ch  ' })).toBeNull();
  });

  it('sends only the changed name, trimmed', () => {
    expect(buildProfilePatch(ALICE, { name: '  Alice Keller  ', email: 'alice@example.ch' })).toStrictEqual({
      name: 'Alice Keller',
    });
  });

  it('sends only the changed email, trimmed', () => {
    expect(buildProfilePatch(ALICE, { name: 'Alice Muster', email: '  alice.keller@example.ch ' })).toStrictEqual({
      email: 'alice.keller@example.ch',
    });
  });

  it('sends both when both changed', () => {
    expect(buildProfilePatch(ALICE, { name: 'Alice Keller', email: 'alice.keller@example.ch' })).toStrictEqual({
      name: 'Alice Keller',
      email: 'alice.keller@example.ch',
    });
  });

  it.each(['', '   '])('never clears the name: %j is not a change', (name) => {
    expect(buildProfilePatch(ALICE, { name, email: 'alice@example.ch' })).toBeNull();
  });

  it('an empty name with a changed email sends only the email', () => {
    expect(buildProfilePatch(ALICE, { name: '  ', email: 'alice.keller@example.ch' })).toStrictEqual({
      email: 'alice.keller@example.ch',
    });
  });

  it('a capitalization change of the email is a change', () => {
    expect(buildProfilePatch(ALICE, { name: 'Alice Muster', email: 'Alice@Example.ch' })).toStrictEqual({
      email: 'Alice@Example.ch',
    });
  });

  it('a capitalization change of the name is a change', () => {
    expect(buildProfilePatch(ALICE, { name: 'alice muster', email: 'alice@example.ch' })).toStrictEqual({
      name: 'alice muster',
    });
  });

  it('a user without a name: an empty input is no change, a new name is', () => {
    expect([
      buildProfilePatch(CARLA, { name: '', email: 'carla@example.ch' }),
      buildProfilePatch(CARLA, { name: ' Carla Rossi ', email: 'carla@example.ch' }),
    ]).toStrictEqual([null, { name: 'Carla Rossi' }]);
  });

  it('never includes the role or any other field', () => {
    const patch = buildProfilePatch(ALICE, { name: 'Alice Keller', email: 'alice.keller@example.ch' });

    expect(Object.keys(patch ?? {}).sort()).toEqual(['email', 'name']);
  });
});

// --- Error messages -----------------------------------------------------------------

describe('orgUserErrorMessage', () => {
  const ROWS: ReadonlyArray<[string, () => unknown, 'user' | 'invitation' | undefined, string]> = [
    ['409 last_admin', () => apiError(409, 'last_admin'), undefined, 'orgUsers.error.lastAdmin'],
    ['409 email_taken', () => apiError(409, 'email_taken'), undefined, 'orgUsers.error.emailTaken'],
    ['409 seat_limit', () => apiError(409, 'seat_limit'), 'invitation', 'orgUsers.error.seatLimit'],
    ['409 invalid_status', () => apiError(409, 'invalid_status'), undefined, 'orgUsers.error.invalidStatus'],
    ['404 (default subject)', () => apiError(404), undefined, 'orgUsers.error.userNotFound'],
    ['404 for a user', () => apiError(404), 'user', 'orgUsers.error.userNotFound'],
    ['404 for an invitation', () => apiError(404), 'invitation', 'orgUsers.error.invitationNotFound'],
    ['422', () => apiError(422), undefined, 'orgUsers.error.invalidInput'],
    ['422 with an unknown reason', () => apiError(422, 'too_short'), undefined, 'orgUsers.error.invalidInput'],
    ['429', () => apiError(429), undefined, 'orgUsers.error.rateLimited'],
    ['429 for an invitation', () => apiError(429), 'invitation', 'orgUsers.error.rateLimited'],
    ['403', () => apiError(403), undefined, 'orgUsers.error.forbidden'],
    ['409 without a reason', () => apiError(409), undefined, 'orgUsers.error.generic'],
    ['409 with an unknown reason', () => apiError(409, 'something_else'), undefined, 'orgUsers.error.generic'],
    ['500', () => apiError(500), undefined, 'orgUsers.error.generic'],
    ['400', () => apiError(400), 'invitation', 'orgUsers.error.generic'],
    ['401', () => apiError(401), undefined, 'orgUsers.error.generic'],
  ];

  it.each(ROWS)('%s → its catalog message', (_label, make, subject, key) => {
    expect(orgUserErrorMessage(make(), subject)).toBe(catalogText('en', key));
  });

  it.each([
    ['last_admin on a 422', apiError(422, 'last_admin'), 'orgUsers.error.lastAdmin'],
    ['email_taken on a 404', apiError(404, 'email_taken'), 'orgUsers.error.emailTaken'],
    ['seat_limit on a 429', apiError(429, 'seat_limit'), 'orgUsers.error.seatLimit'],
    ['invalid_status on a 403', apiError(403, 'invalid_status'), 'orgUsers.error.invalidStatus'],
  ])('a reason beats the status (%s)', (_label, error, key) => {
    expect(orgUserErrorMessage(error, 'invitation')).toBe(catalogText('en', key));
  });

  const NON_API_ERRORS: ReadonlyArray<[string, unknown]> = [
    ['a plain Error', new Error(SECRET_DETAIL)],
    ['a network TypeError', new TypeError(`Failed to fetch ${SECRET_DETAIL}`)],
    ['an Error carrying a status', Object.assign(new Error(SECRET_DETAIL), { status: 404, reason: 'last_admin' })],
    ['an ApiError-shaped plain object', { status: 409, reason: 'last_admin', message: SECRET_DETAIL }],
    ['a string', SECRET_DETAIL],
    ['undefined', undefined],
    ['null', null],
    ['a number', 409],
  ];

  it.each(NON_API_ERRORS)('%s → the generic message', (_label, error) => {
    expect(orgUserErrorMessage(error)).toBe(catalogText('en', 'orgUsers.error.generic'));
  });

  it('never returns the backend detail or the error message, whatever the error', () => {
    const inputs: unknown[] = [
      ...ROWS.map(([, make]) => make()),
      apiError(409, 'last_admin', SECRET_DETAIL),
      apiError(418, undefined, SECRET_DETAIL),
      ...NON_API_ERRORS.map(([, error]) => error),
    ];

    const leaks = inputs
      .map((error) => orgUserErrorMessage(error))
      .filter((text) => text.includes('SECRET') || text.includes('<script>'));

    expect(leaks).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('translates into the active locale (%s)', (locale) => {
    setLocale(locale);

    expect([
      orgUserErrorMessage(apiError(409, 'last_admin')),
      orgUserErrorMessage(apiError(404), 'invitation'),
      orgUserErrorMessage(undefined),
    ]).toEqual([
      catalogText(locale, 'orgUsers.error.lastAdmin'),
      catalogText(locale, 'orgUsers.error.invitationNotFound'),
      catalogText(locale, 'orgUsers.error.generic'),
    ]);
  });
});

// --- Tabs ------------------------------------------------------------------------------

describe('orgTabFrom', () => {
  it("maps 'permissions' to the permissions tab", () => {
    expect(orgTabFrom('permissions')).toBe('permissions');
  });

  it.each(
    (
      [undefined, null, '', 'users', 'PERMISSIONS', ' permissions', 'permissions ', '__proto__', ['permissions'], {}, 1] as unknown[]
    ).map((value): [unknown] => [value]),
  )(
    'maps %j to the users tab',
    (value) => {
      expect(orgTabFrom(value)).toBe('users');
    },
  );

  // Issue #169: the Organization page gets a Settings tab (`?tab=settings`).

  it("maps 'settings' to the settings tab (issue #169)", () => {
    expect(orgTabFrom('settings')).toBe('settings');
  });

  it('maps every tab value to itself, users, settings and permissions (issue #169)', () => {
    const tabs: OrgTab[] = ['users', 'settings', 'permissions'];

    expect(tabs.map((tab) => orgTabFrom(tab))).toEqual(['users', 'settings', 'permissions']);
  });

  it("selects the settings tab only for the exact string 'settings'; near misses fall back to users (issue #169)", () => {
    const nearMisses: unknown[] = ['SETTINGS', 'Settings', ' settings', 'settings ', 'settings\n', ['settings'], { tab: 'settings' }];

    expect({
      exact: orgTabFrom('settings'),
      nearMisses: nearMisses.map((value) => orgTabFrom(value)),
    }).toEqual({
      exact: 'settings',
      nearMisses: ['users', 'users', 'users', 'users', 'users', 'users', 'users'],
    });
  });
});

// --- Confirm sheet copy ----------------------------------------------------------------

describe('confirmCopy', () => {
  const KINDS: readonly PendingKind[] = [
    'role',
    'deactivate',
    'reactivate',
    'resetPassword',
    'forceLogout',
    'delete',
    'revokeInvitation',
  ];

  const KEY_SEGMENT: Record<PendingKind, string> = {
    role: 'role',
    deactivate: 'deactivate',
    reactivate: 'reactivate',
    resetPassword: 'resetPassword',
    forceLogout: 'forceLogout',
    delete: 'delete',
    revokeInvitation: 'revoke',
  };

  const DESTRUCTIVE: Record<PendingKind, boolean> = {
    role: false,
    deactivate: true,
    reactivate: false,
    resetPassword: false,
    forceLogout: true,
    delete: true,
    revokeInvitation: true,
  };

  /** Pinned here (not read from ROLE_LABEL_KEYS) so the role label isn't checked against itself. */
  const ROLE_KEYS: Record<MemberRole, string> = {
    org_admin: 'auth.role.orgAdmin',
    editor: 'auth.role.editor',
    viewer: 'auth.role.viewer',
  };

  const SUBJECT = 'Alice Muster';

  function expected(
    locale: CatalogLocale,
    kind: PendingKind,
    subject: string,
    opts: { role?: MemberRole; isSelf?: boolean } = {},
  ): { heading: string; subtext: string; confirmLabel: string; destructive: boolean } {
    const base = `orgUsers.confirm.${KEY_SEGMENT[kind]}`;
    const params: Record<string, string> = { name: subject };
    if (opts.role !== undefined) params.role = catalogText(locale, ROLE_KEYS[opts.role]);
    const subtext = catalogText(locale, `${base}.subtext`, params);
    return {
      heading: catalogText(locale, `${base}.heading`, params),
      subtext: opts.isSelf ? `${subtext} ${catalogText(locale, 'orgUsers.confirm.selfWarning')}` : subtext,
      confirmLabel: catalogText(locale, `${base}.confirm`, params),
      destructive: DESTRUCTIVE[kind],
    };
  }

  function optsFor(kind: PendingKind): { role?: MemberRole } {
    return kind === 'role' ? { role: 'org_admin' } : {};
  }

  const CASES = LOCALES.flatMap((locale) => KINDS.map((kind) => [locale, kind] as const));

  it.each(CASES)('%s %s: the catalog copy with the subject substituted', (locale, kind) => {
    setLocale(locale);

    expect(confirmCopy(kind, SUBJECT, optsFor(kind))).toEqual(expected(locale, kind, SUBJECT, optsFor(kind)));
  });

  it.each(KINDS)('%s: the subject appears in the heading or the subtext', (kind) => {
    const copy = confirmCopy(kind, SUBJECT, optsFor(kind));

    expect(`${copy.heading} ${copy.subtext}`).toContain(SUBJECT);
  });

  it.each(KINDS)('%s: no placeholder is left unfilled', (kind) => {
    const copy = confirmCopy(kind, SUBJECT, optsFor(kind));

    expect([copy.heading, copy.subtext, copy.confirmLabel].filter((text) => /\{[A-Za-z_]/.test(text))).toEqual([]);
  });

  it('destructive is true exactly for deactivate, forceLogout, delete and revokeInvitation', () => {
    const destructiveKinds = KINDS.filter((kind) => confirmCopy(kind, SUBJECT, optsFor(kind)).destructive);

    expect(destructiveKinds).toEqual(['deactivate', 'forceLogout', 'delete', 'revokeInvitation']);
  });

  it.each(['org_admin', 'editor'] as const)('role: the subtext names the new role label (%s)', (role) => {
    setLocale('de');

    const copy = confirmCopy('role', SUBJECT, { role });

    expect({ copy, label: copy.subtext.includes(catalogText('de', ROLE_KEYS[role])) }).toEqual({
      copy: expected('de', 'role', SUBJECT, { role }),
      label: true,
    });
  });

  it('revokeInvitation: the invitation email is the subject', () => {
    const copy = confirmCopy('revokeInvitation', 'erik@example.ch');

    expect(copy).toEqual(expected('en', 'revokeInvitation', 'erik@example.ch'));
  });

  it('inserts the subject literally (no placeholder or $-pattern expansion)', () => {
    const tricky = 'Zoë {role} $& $1 <b>x</b>';

    expect(confirmCopy('role', tricky, { role: 'editor' })).toEqual(
      expected('en', 'role', tricky, { role: 'editor' }),
    );
  });

  const SELF_KINDS: readonly PendingKind[] = ['deactivate', 'delete', 'role'];

  it.each(LOCALES.flatMap((locale) => SELF_KINDS.map((kind) => [locale, kind] as const)))(
    '%s %s on your own account: the subtext ends with the self warning',
    (locale, kind) => {
      setLocale(locale);

      const copy = confirmCopy(kind, SUBJECT, { ...optsFor(kind), isSelf: true });

      expect({
        copy,
        endsWithWarning: copy.subtext.endsWith(` ${catalogText(locale, 'orgUsers.confirm.selfWarning')}`),
      }).toEqual({ copy: expected(locale, kind, SUBJECT, { ...optsFor(kind), isSelf: true }), endsWithWarning: true });
    },
  );

  it.each(SELF_KINDS)('%s with isSelf false: no self warning', (kind) => {
    const copy = confirmCopy(kind, SUBJECT, { ...optsFor(kind), isSelf: false });

    expect({
      copy,
      warned: copy.subtext.includes(catalogText('en', 'orgUsers.confirm.selfWarning')),
    }).toEqual({ copy: expected('en', kind, SUBJECT, optsFor(kind)), warned: false });
  });
});

// --- No content in logs ---------------------------------------------------------------

describe('org users services logging', () => {
  it('never writes to the console (no names or emails in logs)', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    filterUsers(USERS, f('alice'));
    filterInvitations(INVITATIONS, f('erik'));
    displayName(ALICE);
    isPlausibleEmail('not an email');
    buildProfilePatch(ALICE, { name: 'Alice Keller', email: 'alice.keller@example.ch' });
    orgUserErrorMessage(apiError(409, 'last_admin'));
    orgUserErrorMessage(new Error(SECRET_DETAIL));
    seatLabel({ used: 7, limit: 10 });
    confirmCopy('delete', 'Alice Muster', { isSelf: true });
    orgTabFrom('permissions');

    expect(spies.map((spy) => spy.mock.calls.length)).toEqual([0, 0, 0, 0, 0]);
  });
});
