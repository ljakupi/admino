/**
 * Platform console helper tests (issue #168: Platform console UI, Super Admin;
 * helpers added by the security audit's fix round, findings L1, I2 and I5).
 *
 * - `applyPatch(draft, patch)` (`services/platformDefaults.ts`, L1): the
 *   defaults store rebases the admin's edits onto freshly loaded settings
 *   with it. It returns a copy (the input draft is untouched and later edits
 *   of the copy don't reach it), applies only the patch's fields, per section
 *   (the other fields of a section keep their value), ignores what isn't a
 *   draft section (`confirm_residency_orgs`), and a `null` or empty patch
 *   gives an equal copy.
 * - `orgStatusLabel`, `userStatusLabel`, `memberRoleLabel`
 *   (`services/platformOrgs.ts`, I2): a known server value gives its catalog
 *   text in the active locale; any other value (an unknown status, `''`,
 *   `Object.prototype` member names such as `__proto__` or `constructor`, a
 *   value of another vocabulary, a number, `null`, `undefined`) gives the
 *   helper's neutral fallback: one non-empty string that is neither a known
 *   label nor a raw catalog key nor the value itself. They never throw.
 * - `UUID_RE` (`api/ids.ts`, I5): the one UUID check behind the API client's
 *   path-injection guard and the `?org=` guard. It accepts lower-, upper- and
 *   mixed-case UUIDs, refuses traversal, suffixes, whitespace and other
 *   near-UUIDs, and is stateless. `api/platform.ts` (org and user ids) and
 *   `orgIdFrom` agree with it value by value.
 *
 * Security notes: server-supplied values are never trusted as map keys
 * (prototype members can't leak into a label), and no id outside the UUID
 * format reaches a URL. `fetch` is a stub (no network); a refused id must not
 * call it. No component is mounted.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { UUID_RE } from '@/api/ids';
import { deactivatePlatformUser, getPlatformOrgMetadata } from '@/api/platform';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { applyPatch, type DefaultsDraft } from '@/services/platformDefaults';
import { memberRoleLabel, orgIdFrom, orgStatusLabel, userStatusLabel } from '@/services/platformOrgs';
import type { PlatformSettingsPatch } from '@/api/types';

type Locale = 'en' | 'de' | 'fr';
type Catalog = Record<string, unknown>;

const CATALOGS: Readonly<Record<Locale, Catalog>> = { en, de, fr };

/** The catalog text of `key` in `locale`; throws when the catalog has no non-empty string for it. */
function catalogText(locale: Locale, key: string): string {
  const catalog = CATALOGS[locale];
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`the ${locale} catalog has no text for ${key}`);
  return value;
}

/** A promise's rejection reason, or `undefined` when it fulfils (also catches a synchronous throw). */
async function rejectionOf(call: () => Promise<unknown>): Promise<unknown> {
  try {
    await call();
    return undefined;
  } catch (e) {
    return e;
  }
}

/** What `fn()` returns, or `{ threw }` when it throws. */
function outcome(fn: () => unknown): unknown {
  try {
    return fn();
  } catch (e) {
    return { threw: e };
  }
}

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  localStorage.clear();
  setLocale('en');
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  setLocale('en');
});

// --- applyPatch ------------------------------------------------------------------

/** A full draft (every editable field) with distinct values. */
function draft(): DefaultsDraft {
  return {
    llm: {
      provider: 'infomaniak',
      infomaniak_model: 'qwen3',
      vllm_model: '',
      anthropic_model: 'claude-sonnet-4-5',
      openai_model: 'gpt-4o',
      max_input_tokens: 200000,
      image_input: true,
      max_retries: 2,
    },
    limits: {
      max_tool_calls_per_message: 10,
      max_pending_confirmations: 3,
      confirmation_timeout_s: 300,
      max_message_length: 4000,
      max_context_messages: 20,
    },
    files: { max_file_size_mb: 50, max_files_per_message: 10, max_pages_per_file: 100, render_dpi: 150 },
    retention: { trash_min_days: 0, trash_max_days: 90, audit_months: 12, org_deletion_grace_days: 30 },
    security: {
      rate_limit_per_minute: 20,
      lockout_after_failures: 10,
      lockout_window_minutes: 15,
      lockout_minutes: 15,
      session_idle_timeout_minutes: 60,
      session_max_lifetime_hours: 12,
    },
  };
}

/** Writes a marker into every field of every section of `target` (to prove it is independent of another draft). */
function scribble(target: DefaultsDraft): void {
  target.llm.provider = 'vllm';
  target.llm.image_input = false;
  target.llm.max_retries = 5;
  target.limits.max_context_messages = 199;
  target.files.render_dpi = 299;
  target.retention.audit_months = 83;
  target.security.lockout_minutes = 1439;
}

describe('applyPatch', () => {
  it('applies only the patch fields, per section; every other field keeps its value', () => {
    const patch: PlatformSettingsPatch = {
      llm: { provider: 'openai', openai_model: 'gpt-4.1' },
      files: { render_dpi: 200 },
      security: { lockout_after_failures: 5 },
    };

    const result = applyPatch(draft(), patch);

    const expected = draft();
    expected.llm.provider = 'openai';
    expected.llm.openai_model = 'gpt-4.1';
    expected.files.render_dpi = 200;
    expected.security.lockout_after_failures = 5;
    expect(result).toStrictEqual(expected);
  });

  it('leaves the input draft untouched and returns an independent copy', () => {
    const input = draft();

    const result = applyPatch(input, { llm: { provider: 'anthropic' }, limits: { max_context_messages: 40 } });
    const inputRightAfter = JSON.stringify(input);
    scribble(result);

    expect({ inputRightAfter, inputAfterEditingResult: JSON.stringify(input), same: result === input }).toStrictEqual({
      inputRightAfter: JSON.stringify(draft()),
      inputAfterEditingResult: JSON.stringify(draft()),
      same: false,
    });
  });

  it.each<[string, PlatformSettingsPatch | null]>([
    ['a null patch', null],
    ['an empty patch', {}],
    ['a patch with empty sections', { llm: {}, limits: {}, files: {}, retention: {}, security: {} }],
    ['a patch with only the residency count', { confirm_residency_orgs: 4 }],
  ])('gives an equal, independent copy for %s', (_label, patch) => {
    const input = draft();

    const result = applyPatch(input, patch);
    const equal = JSON.parse(JSON.stringify(result)) as unknown;
    scribble(result);

    expect({ equal, same: result === input, input }).toStrictEqual({ equal: draft(), same: false, input: draft() });
  });

  it('does not keep a reference to the patch: editing the patch afterwards does not change the result', () => {
    const patch = { security: { lockout_after_failures: 5 } };

    const result = applyPatch(draft(), patch);
    patch.security.lockout_after_failures = 99;

    expect(result.security.lockout_after_failures).toBe(5);
  });
});

// --- Label helpers ---------------------------------------------------------------

type LabelHelper = (value: unknown) => string;

interface HelperCase {
  helper: LabelHelper;
  /** Known server value -> catalog key. */
  known: ReadonlyArray<[string, string]>;
  /** Values of the other vocabularies: unknown to this helper. */
  foreign: readonly string[];
}

const HELPERS: ReadonlyArray<[string, HelperCase]> = [
  [
    'orgStatusLabel',
    {
      helper: orgStatusLabel,
      known: [
        ['active', 'platform.orgs.status.active'],
        ['deactivated', 'platform.orgs.status.deactivated'],
        ['pending_deletion', 'platform.orgs.status.pendingDeletion'],
      ],
      foreign: ['invited', 'org_admin', 'pendingDeletion'],
    },
  ],
  [
    'userStatusLabel',
    {
      helper: userStatusLabel,
      known: [
        ['active', 'platform.users.status.active'],
        ['deactivated', 'platform.users.status.deactivated'],
        ['invited', 'platform.users.status.invited'],
      ],
      foreign: ['pending_deletion', 'editor'],
    },
  ],
  [
    'memberRoleLabel',
    {
      helper: memberRoleLabel,
      known: [
        ['org_admin', 'auth.role.orgAdmin'],
        ['editor', 'auth.role.editor'],
        ['viewer', 'auth.role.viewer'],
      ],
      foreign: ['active', 'invited', 'orgAdmin', 'super_admin'],
    },
  ],
];

/** Unknown to every helper. */
const UNKNOWN_VALUES: readonly unknown[] = [
  'archived',
  '',
  '__proto__',
  'constructor',
  'toString',
  'hasOwnProperty',
  'valueOf',
  42,
  0,
  null,
  undefined,
];

/** Every label text of every helper in every locale. */
const ALL_LABELS: ReadonlySet<string> = new Set(
  HELPERS.flatMap(([, { known }]) =>
    known.flatMap(([, key]) => (['en', 'de', 'fr'] as const).map((locale) => catalogText(locale, key))),
  ),
);

const KEY_SHAPE_RE = /^[a-z][A-Za-z0-9]*(\.[A-Za-z0-9_]+)+$/;

describe.each(HELPERS)('%s', (_name, { helper, known, foreign }) => {
  it.each<[Locale]>([['en'], ['de']])('gives the catalog text for every known value (%s)', (locale) => {
    setLocale(locale);

    const labels = known.map(([value]) => helper(value));

    expect(labels).toStrictEqual(known.map(([, key]) => catalogText(locale, key)));
  });

  it('has one neutral fallback: a non-empty string that is no label, no catalog key and no echo', () => {
    const fallback = outcome(() => helper('archived'));

    expect({
      type: typeof fallback,
      empty: typeof fallback === 'string' && fallback.trim() === '',
      isLabel: typeof fallback === 'string' && ALL_LABELS.has(fallback),
      isCatalogKey: typeof fallback === 'string' && (Object.hasOwn(en, fallback) || KEY_SHAPE_RE.test(fallback)),
      echoes: typeof fallback === 'string' && fallback.includes('archived'),
    }).toStrictEqual({ type: 'string', empty: false, isLabel: false, isCatalogKey: false, echoes: false });
  });

  it.each<[Locale]>([['en'], ['de']])(
    'gives that fallback, without throwing, for every unknown or foreign value (%s)',
    (locale) => {
      setLocale(locale);
      const fallback = outcome(() => helper('archived'));
      const values = [...UNKNOWN_VALUES, ...foreign];

      const results = values.map((value) => outcome(() => helper(value)));

      expect({ fallbackIsString: typeof fallback === 'string', results }).toStrictEqual({
        fallbackIsString: true,
        results: values.map(() => fallback),
      });
    },
  );
});

// --- The shared UUID check -------------------------------------------------------

const LOWER = '5a1c2e3f-4b5d-4e6f-8a7b-9c0d1e2f3a4b';
const USER_ID = 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e';

const ACCEPTED: ReadonlyArray<[string, string]> = [
  ['a lower-case UUID', LOWER],
  ['an upper-case UUID', LOWER.toUpperCase()],
  ['a mixed-case UUID', '5A1c2E3f-4B5d-4E6f-8A7b-9C0d1E2f3A4b'],
  ['a time-based UUID', '6ba7b810-9dad-11d1-80b4-00c04fd430c8'],
];

const REFUSED: ReadonlyArray<[string, string]> = [
  ['empty', ''],
  ['a parent path', '../x'],
  ['a UUID behind a parent path', `../${LOWER}`],
  ['a UUID followed by a parent path', `${LOWER}/../users`],
  ['a UUID with a trailing slash', `${LOWER}/`],
  ['an encoded traversal', '..%2F..%2Fsettings'],
  ['a UUID with an encoded slash', `${LOWER}%2f..`],
  ['a UUID with a letter suffix', `${LOWER}x`],
  ['a UUID with an extra hex digit', `${LOWER}0`],
  ['a UUID with a query', `${LOWER}?x=1`],
  ['a UUID with a fragment', `${LOWER}#x`],
  ['a leading space', ` ${LOWER}`],
  ['a trailing space', `${LOWER} `],
  ['a leading newline', `\n${LOWER}`],
  ['a trailing newline', `${LOWER}\n`],
  ['a trailing tab', `${LOWER}\t`],
  ['a trailing line separator', `${LOWER} `],
  ['a braced UUID', `{${LOWER}}`],
  ['a URN', `urn:uuid:${LOWER}`],
  ['a UUID without dashes', LOWER.replace(/-/g, '')],
  ['a UUID one digit short', LOWER.slice(0, -1)],
  ['a non-hex character', LOWER.replace('5a1c', '5a1g')],
  ['dashes in the wrong places', '5a1c2e3f4-b5d-4e6f-8a7b-9c0d1e2f3a4b'],
  ['36 dashes', '-'.repeat(36)],
  ['two UUIDs', `${LOWER}${LOWER}`],
  ['__proto__', '__proto__'],
];

/** The UUID check's verdict, read three ways from the API client and the services. */
async function verdicts(id: string): Promise<{
  shared: boolean;
  orgIdFrom: boolean;
  apiOrgId: boolean;
  apiUserId: boolean;
}> {
  const metadata = { seats: { used: 1, limit: 5 }, storage_used_bytes: 0, chat_count: 0, file_count: 0 };
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(metadata), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ),
  );

  /** True when the call went to the network, false when the id guard refused it before any request. */
  async function accepted(call: () => Promise<unknown>): Promise<boolean> {
    fetchMock.mockClear();
    const error = await rejectionOf(call);
    const refused = error instanceof Error && error.message === 'Invalid id';
    if (!refused && error !== undefined) throw error;
    if (refused === (fetchMock.mock.calls.length > 0)) throw new Error('a refused id reached fetch or an accepted one did not');
    return !refused;
  }

  return {
    shared: UUID_RE.test(id),
    orgIdFrom: orgIdFrom(id) === id,
    apiOrgId: await accepted(() => getPlatformOrgMetadata(id)),
    apiUserId: await accepted(() => deactivatePlatformUser(LOWER, id)),
  };
}

describe('UUID_RE and the guards that share it', () => {
  it.each(ACCEPTED)('every guard accepts %s', async (_label, id) => {
    expect(await verdicts(id)).toStrictEqual({ shared: true, orgIdFrom: true, apiOrgId: true, apiUserId: true });
  });

  it.each(REFUSED)('every guard refuses %s', async (_label, id) => {
    expect(await verdicts(id)).toStrictEqual({ shared: false, orgIdFrom: false, apiOrgId: false, apiUserId: false });
  });

  it('is stateless: the same value gets the same answer on every call', () => {
    const answers = [LOWER, LOWER, `${LOWER}x`, LOWER, USER_ID, USER_ID].map((id) => UUID_RE.test(id));

    expect(answers).toStrictEqual([true, true, false, true, true, true]);
  });

  it('puts an accepted id into the request path unchanged', async () => {
    const upper = LOWER.toUpperCase();
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })),
    );

    await getPlatformOrgMetadata(upper);
    await deactivatePlatformUser(LOWER, upper);

    expect(fetchMock.mock.calls.map(([path]) => path)).toStrictEqual([
      `/api/platform/orgs/${upper}/metadata`,
      `/api/platform/orgs/${LOWER}/users/${upper}/deactivate`,
    ]);
  });
});
