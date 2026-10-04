/**
 * Catalog keys for the Organization → Settings tab (issue #169: Organization
 * profile, policies and instructions; contract GH-169 §7 "i18n keys"; all
 * UI strings go through the i18n catalogs with en/de/fr entries, Swiss
 * Standard German and formal French, #139 §5).
 *
 * Every key the contract lists exists in the `en`, `de` and `fr` catalogs
 * with its own non-blank text; every de/fr text differs from the en text (no
 * English fallback), and `t` under de/fr resolves it to that locale's own
 * text, never the raw key or the en text. A key with a `{count}` placeholder
 * may be a plural message (an `other` form plus LDML categories, every form a
 * non-blank string); every other key is a plain string.
 *
 * Placeholders are exactly the contract's and no others, in every form:
 * `instructions.remaining` and `data.seats` {count}; `data.trashBounds` and
 * the three range issues {min} {max}; `data.storage` {size}; the two
 * too-long issues {max}. Every other new key has none.
 *
 * In each locale the texts of each group are distinct, so the Org Admin can
 * tell them apart: the five error messages, the six validation issues, the
 * six section titles, the residency on/off states, save/reset, and the three
 * Organization tabs (the new Settings tab next to the existing Users and
 * Permissions tabs).
 *
 * The error and issue texts stand in for the backend's answer, which is
 * never shown: none contains "HTTP", an HTTP error status code, braces (other
 * than its listed placeholders) or a snake_case identifier such as the
 * `trash_retention_bounds` reason code.
 *
 * Existing keys the tab reuses are checked for presence only: the language
 * labels `account.language.{de,fr,it,en}`, the store's `toast.common.saved`
 * and the existing `organization.tabs.users|permissions`.
 *
 * The key lists are pinned from the GH-169 contract rather than read from the
 * service, so this file runs on its own; `services/orgSettings.test.ts`
 * cross-checks the strings the functions return. Key-set and placeholder
 * parity between the catalogs is also enforced by `catalogs.test.ts` and
 * `npm run check:i18n`. No component is mounted.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];
const TRANSLATIONS: readonly CatalogLocale[] = ['de', 'fr'];
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const PLURAL_CATEGORIES: ReadonlySet<string> = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);

const P = 'organization.settings';

const TAB_KEY = 'organization.tabs.settings';

const SECTION_TITLE_KEYS: readonly string[] = [
  `${P}.profile.title`,
  `${P}.instructions.title`,
  `${P}.security.title`,
  `${P}.data.title`,
  `${P}.tools.title`,
  `${P}.webAccess.title`,
];

const ISSUE_KEYS: readonly string[] = [
  `${P}.issue.nameRequired`,
  `${P}.issue.nameTooLong`,
  `${P}.issue.instructionsTooLong`,
  `${P}.issue.idleTimeoutRange`,
  `${P}.issue.lifetimeRange`,
  `${P}.issue.trashRetentionRange`,
];

const ERROR_KEYS: readonly string[] = [
  `${P}.error.trashBounds`,
  `${P}.error.invalid`,
  `${P}.error.forbidden`,
  `${P}.error.rateLimited`,
  `${P}.error.generic`,
];

const RESIDENCY_STATE_KEYS: readonly string[] = [`${P}.data.residencyOn`, `${P}.data.residencyOff`];

const ACTION_KEYS: readonly string[] = [`${P}.save`, `${P}.reset`];

/** Every key #169 adds, in the contract's order. */
const NEW_KEYS: readonly string[] = [
  TAB_KEY,
  `${P}.title`,
  `${P}.profile.title`,
  `${P}.profile.displayName`,
  `${P}.profile.responseLanguage`,
  `${P}.instructions.title`,
  `${P}.instructions.hint`,
  `${P}.instructions.remaining`,
  `${P}.security.title`,
  `${P}.security.idleTimeout`,
  `${P}.security.lifetime`,
  `${P}.security.hint`,
  `${P}.data.title`,
  `${P}.data.trashRetention`,
  `${P}.data.trashBounds`,
  `${P}.data.residency`,
  `${P}.data.residencyOn`,
  `${P}.data.residencyOff`,
  `${P}.data.residencyHint`,
  `${P}.data.seats`,
  `${P}.data.storage`,
  `${P}.tools.title`,
  `${P}.tools.permissionsLink`,
  `${P}.tools.mailboxesPlaceholder`,
  `${P}.webAccess.title`,
  `${P}.webAccess.placeholder`,
  ...ACTION_KEYS,
  ...ISSUE_KEYS,
  ...ERROR_KEYS,
];

/** Existing keys the Settings tab and its store reuse unchanged (presence check only). */
const KEPT_KEYS: readonly string[] = [
  'account.language.de',
  'account.language.fr',
  'account.language.it',
  'account.language.en',
  'toast.common.saved',
  'organization.tabs.users',
  'organization.tabs.permissions',
];

/** The only new keys with placeholders (sorted names); every other new key has none. */
const PLACEHOLDERS: Readonly<Record<string, readonly string[]>> = {
  [`${P}.instructions.remaining`]: ['count'],
  [`${P}.data.trashBounds`]: ['max', 'min'],
  [`${P}.data.seats`]: ['count'],
  [`${P}.data.storage`]: ['size'],
  [`${P}.issue.nameTooLong`]: ['max'],
  [`${P}.issue.instructionsTooLong`]: ['max'],
  [`${P}.issue.idleTimeoutRange`]: ['max', 'min'],
  [`${P}.issue.lifetimeRange`]: ['max', 'min'],
  [`${P}.issue.trashRetentionRange`]: ['max', 'min'],
};

/** Keys that may be plural messages (they carry `{count}`). */
const COUNT_KEYS: ReadonlySet<string> = new Set(
  Object.entries(PLACEHOLDERS)
    .filter(([, names]) => names.includes('count'))
    .map(([key]) => key),
);

/** Sample params for every placeholder (numbers small enough to never be grouped). */
const SAMPLE_PARAMS = { count: 42, min: 7, max: 60, size: '7 GiB' };

/** The groups whose texts must be distinct within each locale. */
const DISTINCT_GROUPS: ReadonlyArray<[string, readonly string[]]> = [
  ['settings errors', ERROR_KEYS],
  ['validation issues', ISSUE_KEYS],
  ['section titles', SECTION_TITLE_KEYS],
  ['residency states', RESIDENCY_STATE_KEYS],
  ['save and reset', ACTION_KEYS],
  ['organization tabs', ['organization.tabs.users', 'organization.tabs.permissions', TAB_KEY]],
];

/** Every text the tab shows in place of a backend answer or a refused input. */
const ALL_ERROR_KEYS: readonly string[] = [...ERROR_KEYS, ...ISSUE_KEYS];

/** Patterns that mark an echoed backend answer or a server internal in an error text. */
const RAW_TEXT_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['HTTP', /\bhttps?\b/i],
  // An HTTP error status (4xx/5xx), e.g. "400"; a legitimate limit such as
  // "15 to 120 minutes" is not one.
  ['an HTTP status code', /\b[45]\d\d\b/],
  ['braces', /[{}]/],
  ['a snake_case identifier', /\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b/],
];

/**
 * The forms of the catalog's own message for `key`: `[text]` for a plain
 * string, the plural forms for a `{count}` key's plural message (an `other`
 * form, valid categories, string values). `undefined` for anything else.
 */
function formsOf(catalog: Record<string, unknown>, key: string): string[] | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value === 'string') return [value];
  if (!COUNT_KEYS.has(key) || typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const entries = Object.entries(value as Record<string, unknown>);
  const valid =
    Object.hasOwn(value, 'other') &&
    entries.every(([category, form]) => PLURAL_CATEGORIES.has(category) && typeof form === 'string');
  return valid ? entries.map(([, form]) => form as string) : undefined;
}

/** True when the catalog has its own message for `key` with every form non-blank. */
function hasMessage(catalog: Record<string, unknown>, key: string): boolean {
  const forms = formsOf(catalog, key);
  return forms !== undefined && forms.every((form) => form.trim() !== '');
}

/** The text compared across locales: the string itself, or the plural `other` form. */
function mainTextOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value === 'string') return value;
  if (formsOf(catalog, key) === undefined) return undefined;
  return (value as { other: string }).other;
}

/** A plain-string catalog text (for groups and error texts, which are never plural). */
function textOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** Sorted placeholder names of one form. */
function placeholdersIn(text: string): string[] {
  return [...new Set([...text.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
}

/** `text` with its `{param}`s filled in one literal pass. */
function fill(text: string, params: Record<string, string | number>): string {
  return text.replace(PLACEHOLDER, (match: string, name: string): string =>
    Object.hasOwn(params, name) ? String(params[name]) : match,
  );
}

/** `text` with the key's listed placeholders removed (so only stray braces remain). */
function withoutListedPlaceholders(key: string, text: string): string {
  const allowed = new Set(PLACEHOLDERS[key] ?? []);
  return text.replace(PLACEHOLDER, (match: string, name: string) => (allowed.has(name) ? ' ' : match));
}

/** Names of the raw-text patterns `text` contains. */
function rawTextHits(text: string): string[] {
  return RAW_TEXT_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

/** True when `text` shows `value` as a whole number (not inside a longer one). */
function showsNumber(text: string, value: number): boolean {
  return new RegExp(`(?<!\\d)${value}(?!\\d)`).test(text);
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

describe('i18n organization settings keys added by issue #169', () => {
  it('pins the 39 contract keys without duplicates', () => {
    expect({ count: NEW_KEYS.length, distinct: new Set(NEW_KEYS).size, missingInEn: NEW_KEYS.filter((key) => !hasMessage(en, key)) }).toEqual({
      count: 39,
      distinct: 39,
      missingInEn: [],
    });
  });

  it.each(LOCALES)('gives every new key its own non-blank %s entry and keeps the reused keys', (target) => {
    const catalog = CATALOGS[target];

    expect({
      missingNew: NEW_KEYS.filter((key) => !hasMessage(catalog, key)),
      missingKept: KEPT_KEYS.filter((key) => !Object.hasOwn(catalog, key)),
    }).toEqual({ missingNew: [], missingKept: [] });
  });

  it.each(TRANSLATIONS)('%s translates every new key (its text differs from the en text)', (target) => {
    const untranslated = NEW_KEYS.filter((key) => {
      const source = mainTextOf(en, key);
      const translated = mainTextOf(CATALOGS[target], key);
      return (
        source === undefined ||
        source.trim() === '' ||
        translated === undefined ||
        translated.trim() === '' ||
        translated.trim() === source.trim()
      );
    });

    expect(untranslated).toEqual([]);
  });

  it.each(TRANSLATIONS)("t resolves every new key under %s to that locale's own text, never the raw key", (target) => {
    setLocale(target);

    const wrong = NEW_KEYS.filter((key) => {
      const own = mainTextOf(CATALOGS[target], key);
      const text = t(key as MessageKey, SAMPLE_PARAMS);
      return own === undefined || text === key || text.trim() === '' || text !== fill(own, SAMPLE_PARAMS);
    });

    expect(wrong).toEqual([]);
  });

  it.each(LOCALES)('%s uses exactly the contract placeholders for every new key, in every form', (target) => {
    const catalog = CATALOGS[target];
    const actual = Object.fromEntries(
      NEW_KEYS.map((key) => {
        const forms = formsOf(catalog, key);
        return [key, forms === undefined ? null : forms.map(placeholdersIn)];
      }),
    );
    const wanted = Object.fromEntries(
      NEW_KEYS.map((key) => {
        const forms = formsOf(catalog, key) ?? [''];
        return [key, forms.map(() => [...(PLACEHOLDERS[key] ?? [])])];
      }),
    );

    expect(actual).toEqual(wanted);
  });

  it.each(LOCALES)('%s interpolates every placeholder (no brace is left after t with the params)', (target) => {
    setLocale(target);

    const leftover = NEW_KEYS.filter((key) => {
      const text = t(key as MessageKey, SAMPLE_PARAMS);
      return text === key || /[{}]/.test(text);
    });

    expect(leftover).toEqual([]);
  });
});

describe('i18n organization settings placeholders show their values (issue #169)', () => {
  it.each(LOCALES)('%s remaining-characters text shows the count', (target) => {
    setLocale(target);
    const key = `${P}.instructions.remaining`;

    const texts = [1, 37, 0].map((count) => t(key as MessageKey, { count }));

    expect({
      resolved: texts.every((text) => text !== key),
      shown: [1, 37, 0].map((count, index) => showsNumber(texts[index], count)),
    }).toEqual({ resolved: true, shown: [true, true, true] });
  });

  it.each(LOCALES)('%s seats text shows the seat count', (target) => {
    setLocale(target);
    const key = `${P}.data.seats`;

    const texts = [1, 12].map((count) => t(key as MessageKey, { count }));

    expect({
      resolved: texts.every((text) => text !== key),
      shown: [showsNumber(texts[0], 1), showsNumber(texts[1], 12)],
    }).toEqual({ resolved: true, shown: [true, true] });
  });

  it.each(LOCALES)('%s storage text shows the formatted size', (target) => {
    setLocale(target);
    const key = `${P}.data.storage`;

    const text = t(key as MessageKey, { size: '10 GiB' });

    expect({ resolved: text !== key, shown: text.includes('10 GiB') }).toEqual({ resolved: true, shown: true });
  });

  it.each(LOCALES)('%s bound texts show both bounds', (target) => {
    setLocale(target);
    const keys = [
      `${P}.data.trashBounds`,
      `${P}.issue.idleTimeoutRange`,
      `${P}.issue.lifetimeRange`,
      `${P}.issue.trashRetentionRange`,
    ];

    const missing = keys.filter((key) => {
      const text = t(key as MessageKey, { min: 7, max: 60 });
      return text === key || !showsNumber(text, 7) || !showsNumber(text, 60);
    });

    expect(missing).toEqual([]);
  });

  it.each(LOCALES)('%s too-long texts show the maximum', (target) => {
    setLocale(target);
    const keys = [`${P}.issue.nameTooLong`, `${P}.issue.instructionsTooLong`];

    const missing = keys.filter((key) => {
      const text = t(key as MessageKey, { max: 77 });
      return text === key || !showsNumber(text, 77);
    });

    expect(missing).toEqual([]);
  });
});

describe('i18n organization settings groups are distinct (issue #169)', () => {
  const cases = LOCALES.flatMap((target) => DISTINCT_GROUPS.map(([group, keys]) => ({ target, group, keys })));

  it.each(cases)('the $group texts are distinct in $target', ({ target, keys }) => {
    const values = keys.map((key) => textOf(CATALOGS[target], key));

    expect({
      allText: values.every((value) => typeof value === 'string' && value.trim() !== ''),
      distinct: new Set(values.map((value) => value?.trim())).size,
    }).toEqual({ allText: true, distinct: keys.length });
  });
});

describe('i18n organization settings error texts never look like a backend answer (issue #169)', () => {
  it.each(LOCALES)('%s error and issue texts contain no HTTP, status code, stray brace or snake_case identifier', (target) => {
    const offenders = Object.fromEntries(
      ALL_ERROR_KEYS.flatMap((key) => {
        const text = textOf(CATALOGS[target], key);
        if (text === undefined || text.trim() === '') return [[key, ['missing']]];
        const hits = rawTextHits(withoutListedPlaceholders(key, text));
        return hits.length > 0 ? [[key, hits]] : [];
      }),
    );

    expect({
      // Non-vacuity: the detector flags echoed status lines, reason codes and
      // stray braces, but not a legitimate limit such as 15 to 120 minutes.
      detector: {
        statusLine: rawTextHits('HTTP 400 Bad Request'),
        bareStatus: rawTextHits('Request failed (422).'),
        sentenceEndStatus: rawTextHits('Error 429.'),
        reasonCode: rawTextHits('Refused: trash_retention_bounds'),
        braces: rawTextHits('Invalid {detail}'),
        limit: rawTextHits('Choose 15 to 120 minutes.'),
        placeholdersStripped: withoutListedPlaceholders(`${P}.issue.idleTimeoutRange`, 'From {min} to {max}.'),
      },
      offenders,
    }).toEqual({
      detector: {
        statusLine: ['HTTP', 'an HTTP status code'],
        bareStatus: ['an HTTP status code'],
        sentenceEndStatus: ['an HTTP status code'],
        reasonCode: ['a snake_case identifier'],
        braces: ['braces'],
        limit: [],
        placeholdersStripped: 'From   to  .',
      },
      offenders: {},
    });
  });
});
