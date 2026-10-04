/**
 * Organization settings pure services tests (issue #169: Organization
 * profile, policies and instructions; contract GH-169 §7,
 * `services/orgSettings.ts`).
 *
 * `@/services/orgSettings` holds the framework-free logic the Organization →
 * Settings tab and `stores/orgSettings.ts` share, so it is tested without
 * mounting anything:
 * - constants: `ORG_NAME_MAX` 120, `ORG_INSTRUCTIONS_MAX` 8000, the idle
 *   timeout bounds 15..480 minutes, the lifetime bounds 1..72 hours and
 *   `RESPONSE_LANGUAGES` de, fr, it, en (each has its existing
 *   `account.language.*` label);
 * - `draftFrom(settings)`: the six editable values copied from the response
 *   (the retention is the response's effective value), nothing else;
 * - `validateOrgSettingsDraft(draft, settings)`: the issues in the order of
 *   `OrgSettingsIssue`. The name is trimmed, then must be 1..120 code
 *   points; the instructions are counted verbatim (not trimmed), at most 8000
 *   code points; the idle timeout and the lifetime must be integers in their
 *   bounds (15.5, NaN and Infinity are refused); the retention must be an
 *   integer within the RESPONSE's platform bounds
 *   (`trash_min_days..trash_max_days`), not 0..90. Lengths count code points,
 *   so an emoji (two UTF-16 units) is one character, as in the backend's
 *   Pydantic `max_length`;
 * - `instructionsRemaining(text)`: 8000 minus the code points (negative past
 *   the limit);
 * - `buildOrgSettingsPatch(settings, draft)`: only the fields whose draft
 *   value differs from the response (the display name compared and sent
 *   trimmed; the instructions compared and sent verbatim, `""` clears them),
 *   sections without a change omitted, `null` when nothing changed. Never
 *   `tools`, `data_residency`, `plan` or the retention bounds, even when the
 *   draft object carries such keys (the residency and plan are read-only
 *   for the Org Admin; the tool switches have their own store);
 * - `ORG_SETTINGS_ISSUE_KEYS`: every issue's `organization.settings.issue.*`
 *   catalog key;
 * - `orgSettingsErrorMessage(error)`: catalog text chosen by the `ApiError`'s
 *   `reason` first (`trash_retention_bounds`), then its status (400/422,
 *   403, 429), else the generic text. It NEVER returns the backend's
 *   `detail` nor the error's message (#139 §5: error responses are never
 *   echoed).
 *
 * Expected strings are read from the real en/de/fr catalogs and interpolated
 * here, never hard-coded. Nothing here may write to the console (no
 * instructions text or org name in logs). No component is mounted and
 * nothing touches the network.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { ApiError } from '@/api/client';
import type { OrgSettingsPatch, OrgSettingsResponse, ToolsSettings } from '@/api/types';
import { formatNumber, setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import {
  IDLE_TIMEOUT_MAX,
  IDLE_TIMEOUT_MIN,
  LIFETIME_MAX,
  LIFETIME_MIN,
  ORG_INSTRUCTIONS_MAX,
  ORG_NAME_MAX,
  ORG_SETTINGS_ISSUE_KEYS,
  RESPONSE_LANGUAGES,
  buildOrgSettingsPatch,
  draftFrom,
  instructionsRemaining,
  orgSettingsErrorMessage,
  orgSettingsIssueText,
  planStorageLabel,
  validateOrgSettingsDraft,
  type OrgSettingsDraft,
  type OrgSettingsIssue,
} from '@/services/orgSettings';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/**
 * The catalog's own string for `key` with its `{param}`s filled in one pass.
 * Throws when the catalog has no non-blank string for the key, so a missing
 * key never makes a comparison vacuous.
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

/** A marker the backend's `detail` carries; it must never come back out. */
const SECRET_DETAIL = 'SECRET detail <script>alert(1)</script> Kundenliste Muster';

function apiError(status: number, reason?: string, detail: string = SECRET_DETAIL): ApiError {
  return new ApiError(status, 'Status', detail, reason);
}

/** One code point, two UTF-16 units (U+1F600), so `.length` and code points disagree. */
const EMOJI = '\u{1F600}';

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

// --- Fixtures -------------------------------------------------------------------

const TOOLS: ToolsSettings = {
  gmail: true,
  google_calendar: false,
  google_drive: true,
  outlook: false,
  outlook_calendar: true,
  onedrive: false,
  memory: true,
};

const STORED_INSTRUCTIONS = 'Antworte förmlich.\nNenne nie Kundennamen.';

/** A loaded response; every number distinct so a swapped field never passes. */
const SETTINGS: OrgSettingsResponse = {
  profile: { display_name: 'Treuhand Muster AG', default_response_language: 'de' },
  instructions: STORED_INSTRUCTIONS,
  security: { session_idle_timeout_minutes: 45, session_max_lifetime_hours: 8 },
  retention: { trash_retention_days: 21, trash_min_days: 7, trash_max_days: 60 },
  tools: TOOLS,
  data_residency: true,
  plan: { seats: 25, storage_quota: 10_737_418_240 },
};

/** The draft `draftFrom(SETTINGS)` must produce (written out, not computed). */
const BASE_DRAFT: OrgSettingsDraft = {
  display_name: 'Treuhand Muster AG',
  default_response_language: 'de',
  instructions: STORED_INSTRUCTIONS,
  session_idle_timeout_minutes: 45,
  session_max_lifetime_hours: 8,
  trash_retention_days: 21,
};

function draftWith(overrides: Partial<OrgSettingsDraft>): OrgSettingsDraft {
  return { ...BASE_DRAFT, ...overrides };
}

/** SETTINGS with other platform retention bounds (the effective value given explicitly). */
function withBounds(min: number, max: number, effective: number): OrgSettingsResponse {
  return {
    ...SETTINGS,
    retention: { trash_retention_days: effective, trash_min_days: min, trash_max_days: max },
  };
}

/** A deep copy, to prove an input was not mutated. */
function snapshot<T>(value: T): T {
  return structuredClone(value);
}

// --- Constants --------------------------------------------------------------------

describe('orgSettings constants', () => {
  it('pins the contract bounds and the response languages (each with its existing label key)', () => {
    expect({
      ORG_NAME_MAX,
      ORG_INSTRUCTIONS_MAX,
      IDLE_TIMEOUT_MIN,
      IDLE_TIMEOUT_MAX,
      LIFETIME_MIN,
      LIFETIME_MAX,
      RESPONSE_LANGUAGES: [...RESPONSE_LANGUAGES],
      unlabelled: LOCALES.flatMap((locale) =>
        RESPONSE_LANGUAGES.filter((lang) => !Object.hasOwn(CATALOGS[locale], `account.language.${lang}`)).map(
          (lang) => `${locale}:${lang}`,
        ),
      ),
    }).toEqual({
      ORG_NAME_MAX: 120,
      ORG_INSTRUCTIONS_MAX: 8000,
      IDLE_TIMEOUT_MIN: 15,
      IDLE_TIMEOUT_MAX: 480,
      LIFETIME_MIN: 1,
      LIFETIME_MAX: 72,
      RESPONSE_LANGUAGES: ['de', 'fr', 'it', 'en'],
      unlabelled: [],
    });
  });
});

// --- draftFrom ----------------------------------------------------------------------

describe('orgSettings draftFrom', () => {
  it('copies exactly the six editable values from the response', () => {
    expect(draftFrom(SETTINGS)).toStrictEqual(BASE_DRAFT);
  });

  it('takes the response\'s effective (clamped) retention, not a bound', () => {
    const settings = withBounds(14, 60, 14);

    expect(draftFrom(settings).trash_retention_days).toBe(14);
  });

  it('carries no tools, residency, plan or bounds into the draft', () => {
    const keys = Object.keys(draftFrom(SETTINGS)).sort();

    expect(keys).toEqual([
      'default_response_language',
      'display_name',
      'instructions',
      'session_idle_timeout_minutes',
      'session_max_lifetime_hours',
      'trash_retention_days',
    ]);
  });

  it('returns a copy: editing the draft never changes the response', () => {
    const before = snapshot(SETTINGS);

    const draft = draftFrom(SETTINGS);
    draft.display_name = 'Geändert AG';
    draft.instructions = '';
    draft.session_idle_timeout_minutes = 15;
    draft.trash_retention_days = 60;

    expect({ draft: draft.display_name, settings: SETTINGS }).toEqual({ draft: 'Geändert AG', settings: before });
  });
});

// --- validateOrgSettingsDraft ---------------------------------------------------------

describe('orgSettings validateOrgSettingsDraft valid drafts', () => {
  const cases: Array<[string, Partial<OrgSettingsDraft>]> = [
    ['the loaded draft', {}],
    ['a 1-character name', { display_name: 'A' }],
    ['a 120-character name', { display_name: 'a'.repeat(120) }],
    ['a 120-character name with surrounding spaces (trimmed)', { display_name: `  ${'a'.repeat(120)}  ` }],
    ['a name of 120 emoji (120 code points, 240 UTF-16 units)', { display_name: EMOJI.repeat(120) }],
    ['empty instructions', { instructions: '' }],
    ['8000-character instructions', { instructions: 'a'.repeat(8000) }],
    ['instructions of 8000 emoji (code points, not UTF-16 units)', { instructions: EMOJI.repeat(8000) }],
    ['the lowest idle timeout', { session_idle_timeout_minutes: 15 }],
    ['the highest idle timeout', { session_idle_timeout_minutes: 480 }],
    ['the shortest lifetime', { session_max_lifetime_hours: 1 }],
    ['the longest lifetime', { session_max_lifetime_hours: 72 }],
    ['the retention at the platform minimum', { trash_retention_days: 7 }],
    ['the retention at the platform maximum', { trash_retention_days: 60 }],
    ['another response language', { default_response_language: 'it' }],
  ];

  it.each(cases)('reports no issue for %s', (_label, overrides) => {
    expect(validateOrgSettingsDraft(draftWith(overrides), SETTINGS)).toEqual([]);
  });

  it('accepts 0 and 90 days when the platform bounds are 0..90', () => {
    const settings = withBounds(0, 90, 30);

    expect([
      validateOrgSettingsDraft(draftWith({ trash_retention_days: 0 }), settings),
      validateOrgSettingsDraft(draftWith({ trash_retention_days: 90 }), settings),
    ]).toEqual([[], []]);
  });
});

describe('orgSettings validateOrgSettingsDraft single issues', () => {
  const cases: Array<[string, Partial<OrgSettingsDraft>, OrgSettingsIssue]> = [
    ['an empty name', { display_name: '' }, 'name_required'],
    ['a whitespace-only name', { display_name: ' \t\n  ' }, 'name_required'],
    ['a 121-character name', { display_name: 'a'.repeat(121) }, 'name_too_long'],
    ['a 121-character name inside spaces', { display_name: `  ${'b'.repeat(121)}  ` }, 'name_too_long'],
    ['a name of 121 emoji', { display_name: EMOJI.repeat(121) }, 'name_too_long'],
    ['8001-character instructions', { instructions: 'a'.repeat(8001) }, 'instructions_too_long'],
    ['instructions of 8001 emoji', { instructions: EMOJI.repeat(8001) }, 'instructions_too_long'],
    [
      'instructions over the limit only through surrounding whitespace (counted verbatim)',
      { instructions: `  ${'a'.repeat(7999)}` },
      'instructions_too_long',
    ],
    ['an idle timeout below 15', { session_idle_timeout_minutes: 14 }, 'idle_timeout_range'],
    ['an idle timeout above 480', { session_idle_timeout_minutes: 481 }, 'idle_timeout_range'],
    ['an idle timeout of 0', { session_idle_timeout_minutes: 0 }, 'idle_timeout_range'],
    ['a negative idle timeout', { session_idle_timeout_minutes: -60 }, 'idle_timeout_range'],
    ['a fractional idle timeout', { session_idle_timeout_minutes: 15.5 }, 'idle_timeout_range'],
    ['a NaN idle timeout', { session_idle_timeout_minutes: Number.NaN }, 'idle_timeout_range'],
    ['an infinite idle timeout', { session_idle_timeout_minutes: Number.POSITIVE_INFINITY }, 'idle_timeout_range'],
    ['a lifetime of 0', { session_max_lifetime_hours: 0 }, 'lifetime_range'],
    ['a lifetime above 72', { session_max_lifetime_hours: 73 }, 'lifetime_range'],
    ['a fractional lifetime', { session_max_lifetime_hours: 1.5 }, 'lifetime_range'],
    ['a NaN lifetime', { session_max_lifetime_hours: Number.NaN }, 'lifetime_range'],
    ['an infinite lifetime', { session_max_lifetime_hours: Number.POSITIVE_INFINITY }, 'lifetime_range'],
    ['a retention below the platform minimum', { trash_retention_days: 6 }, 'trash_retention_range'],
    ['a retention above the platform maximum', { trash_retention_days: 61 }, 'trash_retention_range'],
    ['a retention of 0 under a 7-day minimum', { trash_retention_days: 0 }, 'trash_retention_range'],
    ['a retention of 90 under a 60-day maximum', { trash_retention_days: 90 }, 'trash_retention_range'],
    ['a fractional retention', { trash_retention_days: 30.5 }, 'trash_retention_range'],
    ['a NaN retention', { trash_retention_days: Number.NaN }, 'trash_retention_range'],
  ];

  it.each(cases)('reports exactly one issue for %s', (_label, overrides, issue) => {
    expect(validateOrgSettingsDraft(draftWith(overrides), SETTINGS)).toEqual([issue]);
  });

  it('checks the retention against the response\'s bounds, even a single-day window', () => {
    const settings = withBounds(30, 30, 30);

    expect([29, 30, 31].map((days) => validateOrgSettingsDraft(draftWith({ trash_retention_days: days }), settings))).toEqual([
      ['trash_retention_range'],
      [],
      ['trash_retention_range'],
    ]);
  });

  it('refuses -1 and 91 days when the platform bounds are 0..90', () => {
    const settings = withBounds(0, 90, 30);

    expect([
      validateOrgSettingsDraft(draftWith({ trash_retention_days: -1 }), settings),
      validateOrgSettingsDraft(draftWith({ trash_retention_days: 91 }), settings),
    ]).toEqual([['trash_retention_range'], ['trash_retention_range']]);
  });
});

describe('orgSettings validateOrgSettingsDraft several issues', () => {
  it('reports every issue at once in the contract order (empty name)', () => {
    const draft = draftWith({
      display_name: '   ',
      instructions: 'x'.repeat(8001),
      session_idle_timeout_minutes: 14,
      session_max_lifetime_hours: 73,
      trash_retention_days: 61,
    });

    expect(validateOrgSettingsDraft(draft, SETTINGS)).toEqual([
      'name_required',
      'instructions_too_long',
      'idle_timeout_range',
      'lifetime_range',
      'trash_retention_range',
    ]);
  });

  it('reports every issue at once in the contract order (too-long name)', () => {
    const draft = draftWith({
      display_name: 'n'.repeat(121),
      instructions: EMOJI.repeat(8001),
      session_idle_timeout_minutes: Number.NaN,
      session_max_lifetime_hours: 0.5,
      trash_retention_days: 6,
    });

    expect(validateOrgSettingsDraft(draft, SETTINGS)).toEqual([
      'name_too_long',
      'instructions_too_long',
      'idle_timeout_range',
      'lifetime_range',
      'trash_retention_range',
    ]);
  });

  it('keeps the order when only the later issues apply', () => {
    const draft = draftWith({ session_max_lifetime_hours: 100, trash_retention_days: 5, session_idle_timeout_minutes: 500 });

    expect(validateOrgSettingsDraft(draft, SETTINGS)).toEqual([
      'idle_timeout_range',
      'lifetime_range',
      'trash_retention_range',
    ]);
  });

  it('never mutates the draft or the response', () => {
    const draft = draftWith({ display_name: '  Neue AG  ', session_idle_timeout_minutes: 14 });
    const before = { draft: snapshot(draft), settings: snapshot(SETTINGS) };

    const issues = validateOrgSettingsDraft(draft, SETTINGS);

    expect({ issues, draft, settings: SETTINGS }).toEqual({ issues: ['idle_timeout_range'], ...before });
  });
});

// --- instructionsRemaining -------------------------------------------------------------

describe('orgSettings instructionsRemaining', () => {
  const cases: Array<[string, string, number]> = [
    ['empty instructions', '', 8000],
    ['a short text', 'Hallo', 7995],
    ['ten emoji (code points, not UTF-16 units)', EMOJI.repeat(10), 7990],
    ['line breaks and tabs counted verbatim', 'a\r\nb\tc', 7994],
    ['whitespace counted verbatim (not trimmed)', '   ', 7997],
    ['exactly the limit', 'a'.repeat(8000), 0],
    ['one over the limit', 'a'.repeat(8001), -1],
    ['three emoji over the limit', EMOJI.repeat(8003), -3],
  ];

  it.each(cases)('counts %s', (_label, text, remaining) => {
    expect(instructionsRemaining(text)).toBe(remaining);
  });
});

// --- buildOrgSettingsPatch ---------------------------------------------------------------

describe('orgSettings buildOrgSettingsPatch single changes', () => {
  const cases: Array<[string, Partial<OrgSettingsDraft>, OrgSettingsPatch]> = [
    ['a new display name', { display_name: 'Muster Treuhand GmbH' }, { profile: { display_name: 'Muster Treuhand GmbH' } }],
    [
      'a new display name sent trimmed',
      { display_name: '  Muster Treuhand GmbH \t' },
      { profile: { display_name: 'Muster Treuhand GmbH' } },
    ],
    ['a new response language', { default_response_language: 'fr' }, { profile: { default_response_language: 'fr' } }],
    ['new instructions', { instructions: 'Antworte kurz.' }, { instructions: 'Antworte kurz.' }],
    ['cleared instructions', { instructions: '' }, { instructions: '' }],
    [
      'instructions with surrounding whitespace sent verbatim',
      { instructions: '  Antworte kurz.\n\n' },
      { instructions: '  Antworte kurz.\n\n' },
    ],
    [
      'instructions that differ only by a trailing line break (compared verbatim)',
      { instructions: `${STORED_INSTRUCTIONS}\n` },
      { instructions: `${STORED_INSTRUCTIONS}\n` },
    ],
    [
      'a new idle timeout',
      { session_idle_timeout_minutes: 30 },
      { security: { session_idle_timeout_minutes: 30 } },
    ],
    ['a new lifetime', { session_max_lifetime_hours: 24 }, { security: { session_max_lifetime_hours: 24 } }],
    ['a new retention', { trash_retention_days: 60 }, { retention: { trash_retention_days: 60 } }],
  ];

  it.each(cases)('sends only %s', (_label, overrides, patch) => {
    expect(buildOrgSettingsPatch(SETTINGS, draftWith(overrides))).toStrictEqual(patch);
  });

  it('sends a retention of 0 days (a falsy value is still a change)', () => {
    const settings = withBounds(0, 90, 30);
    const draft = { ...draftFrom(settings), trash_retention_days: 0 };

    expect(buildOrgSettingsPatch(settings, draft)).toStrictEqual({ retention: { trash_retention_days: 0 } });
  });
});

describe('orgSettings buildOrgSettingsPatch no change', () => {
  it('returns null for the loaded draft', () => {
    expect(buildOrgSettingsPatch(SETTINGS, draftWith({}))).toBeNull();
  });

  it('returns null for the draft draftFrom builds', () => {
    expect(buildOrgSettingsPatch(SETTINGS, draftFrom(SETTINGS))).toBeNull();
  });

  it('returns null when the display name differs only by surrounding whitespace', () => {
    expect(buildOrgSettingsPatch(SETTINGS, draftWith({ display_name: '  Treuhand Muster AG\t ' }))).toBeNull();
  });

  it('returns null when every value was edited back to the stored one', () => {
    const draft = draftWith({ trash_retention_days: 60, session_idle_timeout_minutes: 15 });
    draft.trash_retention_days = 21;
    draft.session_idle_timeout_minutes = 45;

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toBeNull();
  });

  it('compares the retention with the response\'s effective value', () => {
    const settings = withBounds(14, 60, 14);

    expect(buildOrgSettingsPatch(settings, { ...draftFrom(settings), trash_retention_days: 14 })).toBeNull();
  });
});

describe('orgSettings buildOrgSettingsPatch several changes', () => {
  it('sends both profile fields in one section', () => {
    const draft = draftWith({ display_name: 'Neue AG', default_response_language: 'en' });

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toStrictEqual({
      profile: { display_name: 'Neue AG', default_response_language: 'en' },
    });
  });

  it('leaves out a name that only gained whitespace next to a real language change', () => {
    const draft = draftWith({ display_name: ' Treuhand Muster AG ', default_response_language: 'it' });

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toStrictEqual({ profile: { default_response_language: 'it' } });
  });

  it('sends both security fields in one section', () => {
    const draft = draftWith({ session_idle_timeout_minutes: 480, session_max_lifetime_hours: 72 });

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toStrictEqual({
      security: { session_idle_timeout_minutes: 480, session_max_lifetime_hours: 72 },
    });
  });

  it('sends every changed field in its own section and nothing else', () => {
    const draft: OrgSettingsDraft = {
      display_name: ' Neue Treuhand AG ',
      default_response_language: 'fr',
      instructions: 'Réponds poliment.',
      session_idle_timeout_minutes: 120,
      session_max_lifetime_hours: 1,
      trash_retention_days: 7,
    };

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toStrictEqual({
      profile: { display_name: 'Neue Treuhand AG', default_response_language: 'fr' },
      instructions: 'Réponds poliment.',
      security: { session_idle_timeout_minutes: 120, session_max_lifetime_hours: 1 },
      retention: { trash_retention_days: 7 },
    });
  });

  it('omits the sections that did not change', () => {
    const draft = draftWith({ instructions: '', session_max_lifetime_hours: 12 });

    expect(buildOrgSettingsPatch(SETTINGS, draft)).toStrictEqual({
      instructions: '',
      security: { session_max_lifetime_hours: 12 },
    });
  });

  it('never mutates the response or the draft', () => {
    const draft = draftWith({ display_name: '  Neue AG  ', trash_retention_days: 30 });
    const before = { settings: snapshot(SETTINGS), draft: snapshot(draft) };

    const patch = buildOrgSettingsPatch(SETTINGS, draft);

    expect({ patch, settings: SETTINGS, draft }).toEqual({
      patch: { profile: { display_name: 'Neue AG' }, retention: { trash_retention_days: 30 } },
      ...before,
    });
  });
});

describe('orgSettings buildOrgSettingsPatch read-only values', () => {
  /** A draft object that also carries keys the patch must never send. */
  function draftWithExtras(overrides: Partial<OrgSettingsDraft>): OrgSettingsDraft {
    return {
      ...BASE_DRAFT,
      tools: { ...TOOLS, gmail: false, memory: false },
      data_residency: false,
      plan: { seats: 999, storage_quota: 1 },
      trash_min_days: 0,
      trash_max_days: 90,
      org_id: '7d9f3c2a-1b4e-4c6d-8a9f-0e1d2c3b4a59',
      ...overrides,
    } as OrgSettingsDraft;
  }

  it('returns null when only read-only extras differ', () => {
    expect(buildOrgSettingsPatch(SETTINGS, draftWithExtras({}))).toBeNull();
  });

  it('sends only the real change, never tools, residency, plan, bounds or ids', () => {
    expect(buildOrgSettingsPatch(SETTINGS, draftWithExtras({ trash_retention_days: 30 }))).toStrictEqual({
      retention: { trash_retention_days: 30 },
    });
  });

  it('never names tools, data_residency, plan or the bounds anywhere in the patch JSON', () => {
    const draft = draftWithExtras({
      display_name: 'Neue AG',
      default_response_language: 'en',
      instructions: 'Neu',
      session_idle_timeout_minutes: 20,
      session_max_lifetime_hours: 2,
      trash_retention_days: 8,
    });

    const json = JSON.stringify(buildOrgSettingsPatch(SETTINGS, draft));

    expect({
      sections: Object.keys(JSON.parse(json) as Record<string, unknown>).sort(),
      forbidden: ['tools', 'data_residency', 'plan', 'trash_min_days', 'trash_max_days', 'org_id', 'seats', 'storage_quota'].filter(
        (name) => json.includes(`"${name}"`),
      ),
    }).toEqual({ sections: ['instructions', 'profile', 'retention', 'security'], forbidden: [] });
  });
});

// --- Issue keys ---------------------------------------------------------------------------

describe('orgSettings ORG_SETTINGS_ISSUE_KEYS', () => {
  it('maps every issue to its organization.settings.issue key', () => {
    expect(ORG_SETTINGS_ISSUE_KEYS).toStrictEqual({
      name_required: 'organization.settings.issue.nameRequired',
      name_too_long: 'organization.settings.issue.nameTooLong',
      instructions_too_long: 'organization.settings.issue.instructionsTooLong',
      idle_timeout_range: 'organization.settings.issue.idleTimeoutRange',
      lifetime_range: 'organization.settings.issue.lifetimeRange',
      trash_retention_range: 'organization.settings.issue.trashRetentionRange',
    });
  });

  it.each(LOCALES)('every issue key has its own distinct %s text', (locale) => {
    const texts = Object.values(ORG_SETTINGS_ISSUE_KEYS).map((key) => catalogText(locale, key));

    expect({ count: texts.length, distinct: new Set(texts).size }).toEqual({ count: 6, distinct: 6 });
  });

  it('covers every issue validateOrgSettingsDraft can report', () => {
    const reported = new Set([
      ...validateOrgSettingsDraft(
        draftWith({
          display_name: '',
          instructions: 'x'.repeat(8001),
          session_idle_timeout_minutes: 1,
          session_max_lifetime_hours: 0,
          trash_retention_days: 0,
        }),
        SETTINGS,
      ),
      ...validateOrgSettingsDraft(draftWith({ display_name: 'x'.repeat(121) }), SETTINGS),
    ]);

    expect({
      reported: reported.size,
      unmapped: [...reported].filter((issue) => !Object.hasOwn(ORG_SETTINGS_ISSUE_KEYS, issue)),
    }).toEqual({ reported: 6, unmapped: [] });
  });
});

// --- Error messages -----------------------------------------------------------------------

/** Every error shape the settings flows can see, with the catalog key it must map to. */
const ERROR_CASES: Array<[string, () => unknown, string]> = [
  ['the 400 trash bounds refusal', () => apiError(400, 'trash_retention_bounds'), 'organization.settings.error.trashBounds'],
  ['the trash bounds reason on a 422 (reason first)', () => apiError(422, 'trash_retention_bounds'), 'organization.settings.error.trashBounds'],
  ['the trash bounds reason on a 429 (reason first)', () => apiError(429, 'trash_retention_bounds'), 'organization.settings.error.trashBounds'],
  ['the trash bounds reason on a 500 (reason first)', () => apiError(500, 'trash_retention_bounds'), 'organization.settings.error.trashBounds'],
  ['a 400 without a reason', () => apiError(400), 'organization.settings.error.invalid'],
  ['a 400 with another reason', () => apiError(400, 'last_admin'), 'organization.settings.error.invalid'],
  ['a 422 validation error', () => apiError(422), 'organization.settings.error.invalid'],
  ['a 403', () => apiError(403, undefined, 'Forbidden'), 'organization.settings.error.forbidden'],
  ['a 403 with another reason', () => apiError(403, 'residency_confirmation'), 'organization.settings.error.forbidden'],
  ['a 429', () => apiError(429), 'organization.settings.error.rateLimited'],
  ['a 401', () => apiError(401), 'organization.settings.error.generic'],
  ['a 404', () => apiError(404), 'organization.settings.error.generic'],
  ['a 409', () => apiError(409), 'organization.settings.error.generic'],
  ['a 500', () => apiError(500), 'organization.settings.error.generic'],
  ['a plain Error', () => new Error(SECRET_DETAIL), 'organization.settings.error.generic'],
  ['a network TypeError', () => new TypeError('Failed to fetch'), 'organization.settings.error.generic'],
  ['an abort', () => new DOMException('The operation was aborted.', 'AbortError'), 'organization.settings.error.generic'],
  [
    'a plain object shaped like an ApiError',
    () => ({ status: 400, reason: 'trash_retention_bounds', message: SECRET_DETAIL }),
    'organization.settings.error.generic',
  ],
  ['a bare reason string', () => 'trash_retention_bounds', 'organization.settings.error.generic'],
  ['undefined', () => undefined, 'organization.settings.error.generic'],
  ['null', () => null, 'organization.settings.error.generic'],
];

const ERROR_KEYS: readonly string[] = [
  'organization.settings.error.trashBounds',
  'organization.settings.error.invalid',
  'organization.settings.error.forbidden',
  'organization.settings.error.rateLimited',
  'organization.settings.error.generic',
];

describe('orgSettings orgSettingsErrorMessage', () => {
  it.each(ERROR_CASES)('maps %s to its catalog text', (_label, make, key) => {
    expect(orgSettingsErrorMessage(make())).toBe(catalogText('en', key));
  });

  it.each(LOCALES)('maps every case to the active %s catalog text (the five texts distinct)', (locale) => {
    setLocale(locale);

    const actual = ERROR_CASES.map(([, make]) => orgSettingsErrorMessage(make()));

    expect({
      distinct: new Set(ERROR_KEYS.map((key) => catalogText(locale, key))).size,
      actual,
    }).toEqual({
      distinct: ERROR_KEYS.length,
      actual: ERROR_CASES.map(([, , key]) => catalogText(locale, key)),
    });
  });

  it('never returns the backend detail, the error message or the reason code', () => {
    const shown = [
      ...ERROR_CASES.map(([, make]) => orgSettingsErrorMessage(make())),
      orgSettingsErrorMessage(apiError(400, 'trash_retention_bounds', 'The trash retention must be within the platform\'s bounds.')),
      orgSettingsErrorMessage(apiError(400, 'trash_retention_bounds', catalogText('en', 'organization.settings.error.generic'))),
    ];

    expect({
      leaked: shown.filter(
        (text) =>
          text.includes('SECRET') ||
          text.includes('<script>') ||
          text.includes('trash_retention_bounds') ||
          text.includes("platform's bounds.") ||
          text.includes('Failed to fetch'),
      ),
      fromCatalog: shown.every((text) => ERROR_KEYS.some((key) => catalogText('en', key) === text)),
      lastTwo: shown.slice(-2),
    }).toEqual({
      leaked: [],
      fromCatalog: true,
      lastTwo: [
        catalogText('en', 'organization.settings.error.trashBounds'),
        catalogText('en', 'organization.settings.error.trashBounds'),
      ],
    });
  });
});

// --- No content in logs ----------------------------------------------------------------------

describe('orgSettings services logging', () => {
  it('never writes to the console (no instructions text or org name in logs)', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    const draft = draftFrom(SETTINGS);
    validateOrgSettingsDraft({ ...draft, display_name: '', instructions: 'x'.repeat(8001) }, SETTINGS);
    instructionsRemaining(STORED_INSTRUCTIONS);
    buildOrgSettingsPatch(SETTINGS, { ...draft, instructions: 'Geheim: Kundenliste' });
    orgSettingsErrorMessage(apiError(400, 'trash_retention_bounds'));
    orgSettingsErrorMessage(new Error(SECRET_DETAIL));

    expect(spies.map((spy) => spy.mock.calls.length)).toEqual([0, 0, 0, 0, 0]);
  });
});

// --- Issue texts (logic moved out of OrgSettingsPanel.vue) ---------------------------------

/**
 * `orgSettingsIssueText(issue, settings)` is
 * `t(ORG_SETTINGS_ISSUE_KEYS[issue], params)` with the bounds the validator
 * enforces as params: the name and instructions maxima, the idle timeout and
 * lifetime ranges, and the trash retention range taken from the RESPONSE's
 * platform bounds (SETTINGS: 7..60), or 0..90 when nothing is loaded yet.
 * Params are plain numbers (`String(n)` in the text), never `{…}` leftovers.
 */
const ISSUE_PARAMS: ReadonlyArray<readonly [OrgSettingsIssue, Record<string, number>]> = [
  ['name_required', {}],
  ['name_too_long', { max: 120 }],
  ['instructions_too_long', { max: 8000 }],
  ['idle_timeout_range', { min: 15, max: 480 }],
  ['lifetime_range', { min: 1, max: 72 }],
  ['trash_retention_range', { min: 7, max: 60 }],
];

const ISSUE_TEXT_CASES = LOCALES.flatMap((locale) =>
  ISSUE_PARAMS.map(([issue, params]) => [locale, issue, params] as const),
);

const TRASH_RANGE_KEY = 'organization.settings.issue.trashRetentionRange';

/** True when `n` appears in `text` as a whole number (so "1" is not found inside "15"). */
function showsNumber(text: string, n: number): boolean {
  return new RegExp(`(^|\\D)${n}(\\D|$)`).test(text);
}

describe('orgSettings orgSettingsIssueText', () => {
  it.each(ISSUE_TEXT_CASES)('gives the %s catalog text of %s with its params filled in', (locale, issue, params) => {
    setLocale(locale);

    expect(orgSettingsIssueText(issue, SETTINGS)).toBe(
      catalogText(locale, ORG_SETTINGS_ISSUE_KEYS[issue], params),
    );
  });

  it.each(LOCALES)('leaves no placeholder and shows every bound as a number in %s', (locale) => {
    setLocale(locale);

    const texts = ISSUE_PARAMS.map(([issue, params]) => ({
      issue,
      params,
      text: orgSettingsIssueText(issue, SETTINGS),
    }));

    expect({
      unfilled: texts.filter(({ text }) => text.includes('{') || text.includes('}')).map(({ issue }) => issue),
      missing: texts.flatMap(({ issue, params, text }) =>
        Object.values(params)
          .filter((n) => !showsNumber(text, n))
          .map((n) => `${issue}:${n}`),
      ),
      blank: texts.filter(({ text }) => text.trim() === '').map(({ issue }) => issue),
    }).toEqual({ unfilled: [], missing: [], blank: [] });
  });

  it.each(LOCALES)('falls back to 0..90 days for the trash retention when no settings are loaded (%s)', (locale) => {
    setLocale(locale);

    expect(orgSettingsIssueText('trash_retention_range', null)).toBe(
      catalogText(locale, TRASH_RANGE_KEY, { min: 0, max: 90 }),
    );
  });

  it('takes the trash retention bounds from the response, whatever they are', () => {
    expect([
      orgSettingsIssueText('trash_retention_range', withBounds(14, 45, 20)),
      orgSettingsIssueText('trash_retention_range', withBounds(0, 90, 30)),
    ]).toEqual([
      catalogText('en', TRASH_RANGE_KEY, { min: 14, max: 45 }),
      catalogText('en', TRASH_RANGE_KEY, { min: 0, max: 90 }),
    ]);
  });

  it('gives every other issue the same text with or without loaded settings', () => {
    const others = ISSUE_PARAMS.filter(([issue]) => issue !== 'trash_retention_range');

    expect({
      withoutSettings: others.map(([issue]) => orgSettingsIssueText(issue, null)),
      withSettings: others.map(([issue]) => orgSettingsIssueText(issue, SETTINGS)),
    }).toEqual({
      withoutSettings: others.map(([issue, params]) => catalogText('en', ORG_SETTINGS_ISSUE_KEYS[issue], params)),
      withSettings: others.map(([issue, params]) => catalogText('en', ORG_SETTINGS_ISSUE_KEYS[issue], params)),
    });
  });

  it('follows the active locale: the same issue gives three distinct catalog texts', () => {
    const texts = LOCALES.map((locale) => {
      setLocale(locale);
      return orgSettingsIssueText('idle_timeout_range', SETTINGS);
    });

    expect({ distinct: new Set(texts).size, texts }).toEqual({
      distinct: 3,
      texts: LOCALES.map((locale) =>
        catalogText(locale, 'organization.settings.issue.idleTimeoutRange', { min: 15, max: 480 }),
      ),
    });
  });

  it('never changes the settings it reads and never writes to the console', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
    const before = snapshot(SETTINGS);

    const texts = ISSUE_PARAMS.map(([issue]) => orgSettingsIssueText(issue, SETTINGS));

    expect({
      count: texts.length,
      settings: SETTINGS,
      console: spies.map((spy) => spy.mock.calls.length),
    }).toEqual({ count: 6, settings: before, console: [0, 0, 0, 0, 0] });
  });
});

// --- Plan storage label (logic moved out of OrgSettingsPanel.vue) --------------------------

/**
 * `planStorageLabel(bytes)` is `t('organization.settings.data.storage', { size })`
 * with `size` = the GiB value (bytes / 1024^3, binary, not 1000^3) formatted by
 * `@/i18n`'s `formatNumber` with at most one fraction digit (rounded, no
 * trailing ".0"), then ONE plain space (U+0020) and "GiB". The en sizes are
 * pinned literally; de/fr read the real Swiss formatter so Intl data never
 * makes the test flaky (de-CH writes "1.5", fr-CH "1,5"; both group
 * thousands).
 */
const GIB = 1024 ** 3;
const STORAGE_KEY = 'organization.settings.data.storage';

const STORAGE_CASES: ReadonlyArray<readonly [string, number, string]> = [
  ['10 GiB', 10 * GIB, '10 GiB'],
  ['1.5 GiB', 1.5 * GIB, '1.5 GiB'],
  ['0 bytes', 0, '0 GiB'],
  ['1 GiB and 1 byte (rounded, no trailing .0)', GIB + 1, '1 GiB'],
  ['1.25 GiB (one fraction digit, rounded half up)', 1.25 * GIB, '1.3 GiB'],
  ['2.75 GiB (rounded, not truncated)', 2.75 * GIB, '2.8 GiB'],
  ['10 GiB less 1 byte (rounds up to 10)', 10 * GIB - 1, '10 GiB'],
  ['512 MiB', 512 * 1024 ** 2, '0.5 GiB'],
];

/** Quotas whose Swiss formatting differs by locale (decimal separator, thousands grouping). */
const LOCALE_STORAGE_BYTES: readonly number[] = [
  10 * GIB,
  1.5 * GIB,
  0,
  GIB + 1,
  1.25 * GIB,
  2.75 * GIB,
  1024 * GIB,
  1536.5 * GIB,
];

function expectedStorageLabel(locale: CatalogLocale, bytes: number): string {
  return catalogText(locale, STORAGE_KEY, {
    size: `${formatNumber(bytes / GIB, { maximumFractionDigits: 1 })} GiB`,
  });
}

describe('orgSettings planStorageLabel', () => {
  it.each(STORAGE_CASES)('labels %s (%i bytes) with the size "%s" in en', (_label, bytes, size) => {
    expect(planStorageLabel(bytes)).toBe(catalogText('en', STORAGE_KEY, { size }));
  });

  it.each(LOCALES)('formats the GiB value with the active %s number format (formatNumber, one fraction digit)', (locale) => {
    setLocale(locale);

    expect(LOCALE_STORAGE_BYTES.map((bytes) => planStorageLabel(bytes))).toEqual(
      LOCALE_STORAGE_BYTES.map((bytes) => expectedStorageLabel(locale, bytes)),
    );
  });

  it('groups thousands of GiB with the locale separator (1024 GiB is not "1024 GiB")', () => {
    setLocale('en');

    const label = planStorageLabel(1024 * GIB);

    expect({ label, plain: label.includes('1024 GiB') }).toEqual({
      label: expectedStorageLabel('en', 1024 * GIB),
      plain: false,
    });
  });

  it('follows the active locale: 1.5 GiB gives three distinct labels from their own catalogs', () => {
    const labels = LOCALES.map((locale) => {
      setLocale(locale);
      return planStorageLabel(1.5 * GIB);
    });

    expect({ distinct: new Set(labels).size, labels }).toEqual({
      distinct: 3,
      labels: LOCALES.map((locale) => {
        setLocale(locale);
        return expectedStorageLabel(locale, 1.5 * GIB);
      }),
    });
  });

  it.each(LOCALES)('joins the number and "GiB" with one plain space, never a non-breaking one (%s)', (locale) => {
    setLocale(locale);

    const labels = [1.5 * GIB, 1024 * GIB, GIB + 1, 0].map((bytes) => planStorageLabel(bytes));

    expect(
      labels.filter((label) => !/\d GiB/.test(label) || /[  ]GiB/.test(label) || label.includes('{')),
    ).toEqual([]);
  });

  it('never writes to the console', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    const label = planStorageLabel(SETTINGS.plan.storage_quota);

    expect({ label, console: spies.map((spy) => spy.mock.calls.length) }).toEqual({
      label: catalogText('en', STORAGE_KEY, { size: '10 GiB' }),
      console: [0, 0, 0, 0, 0],
    });
  });
});
