/**
 * Catalog keys for the Platform console (issue #168: Platform console UI for
 * the Super Admin; all strings go through the i18n catalogs with en/de/fr
 * entries and no error response is ever echoed, #139 §5).
 *
 * Every key the console's logic uses (the services' labels, form and error
 * messages, confirm copy and the stores' toasts; GH-168 contract "i18n keys
 * the logic uses") must exist in the `en`, `de` and `fr` catalogs with its
 * own non-blank value; every de/fr value differs from the en value (no
 * English fallback), and `t` under de/fr resolves it to that locale's own
 * text, never the raw key.
 *
 * Placeholders are exactly the contract's and no others:
 * `platform.orgs.seats` {used} {limit}; the org and user confirm headings
 * {name}; `platform.defaults.error.range` {min} {max}. Every other new key
 * has none (the confirm subtexts and labels included).
 *
 * In each locale the texts of each group are distinct, so the Super Admin
 * can tell the outcomes apart: the thirteen `platform.error.*` messages, the
 * five form errors, the five defaults errors, the org confirm copy, the user
 * confirm copy, the thirteen toasts, the org and user status labels and the
 * two tabs.
 *
 * The error texts stand in for the backend's answer, which is never shown:
 * none contains "HTTP", an HTTP error status code, braces (other than its
 * listed placeholders) or a snake_case identifier such as a reason code.
 *
 * The existing residency confirmation keys from #242
 * (`platform.defaults.residencyConfirm.title|body|confirm`) are kept and
 * checked for presence only (`modelPolicyKeys.test.ts` owns their shape).
 *
 * The key lists are pinned from the GH-168 contract rather than read from the
 * services, so this file runs on its own; the service tests cross-check the
 * strings the functions return. Key-set and placeholder parity between the
 * catalogs is also enforced by `catalogs.test.ts` and `npm run check:i18n`.
 * No component is mounted.
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

const TAB_KEYS: readonly string[] = ['platform.tabs.orgs', 'platform.tabs.defaults'];

const ORG_STATUS_KEYS: readonly string[] = [
  'platform.orgs.status.active',
  'platform.orgs.status.deactivated',
  'platform.orgs.status.pendingDeletion',
];

const USER_STATUS_KEYS: readonly string[] = [
  'platform.users.status.active',
  'platform.users.status.deactivated',
  'platform.users.status.invited',
];

const SEATS_KEY = 'platform.orgs.seats';

const FORM_ERROR_KEYS: readonly string[] = [
  'platform.orgs.form.error.name',
  'platform.orgs.form.error.email',
  'platform.orgs.form.error.seats',
  'platform.orgs.form.error.budget',
  'platform.orgs.form.error.storage',
];

const ERROR_KEYS: readonly string[] = [
  'platform.error.generic',
  'platform.error.emailTaken',
  'platform.error.seatLimit',
  'platform.error.orgInvalidStatus',
  'platform.error.userInvalidStatus',
  'platform.error.lastAdmin',
  'platform.error.hasActiveAdmin',
  'platform.error.residencyConfirmation',
  'platform.error.orgNotFound',
  'platform.error.userNotFound',
  'platform.error.invalidInput',
  'platform.error.rateLimited',
  'platform.error.forbidden',
];

const ORG_CONFIRM_KINDS: readonly string[] = [
  'deactivate',
  'reactivate',
  'scheduleDeletion',
  'cancelDeletion',
  'residencyOn',
  'residencyOff',
];

const USER_CONFIRM_KINDS: readonly string[] = ['deactivate', 'reactivate', 'resetPassword'];

const CONFIRM_PARTS: readonly string[] = ['heading', 'subtext', 'confirm'];

const ORG_CONFIRM_KEYS: readonly string[] = ORG_CONFIRM_KINDS.flatMap((kind) =>
  CONFIRM_PARTS.map((part) => `platform.orgs.confirm.${kind}.${part}`),
);

const USER_CONFIRM_KEYS: readonly string[] = USER_CONFIRM_KINDS.flatMap((kind) =>
  CONFIRM_PARTS.map((part) => `platform.users.confirm.${kind}.${part}`),
);

const DEFAULTS_ERROR_KEYS: readonly string[] = [
  'platform.defaults.error.range',
  'platform.defaults.error.modelName',
  'platform.defaults.error.provider',
  'platform.defaults.error.invalid',
  'platform.defaults.error.trashOrder',
];

const TOAST_KEYS: readonly string[] = [
  'platform.toast.orgCreated',
  'platform.toast.limitsSaved',
  'platform.toast.orgDeactivated',
  'platform.toast.orgReactivated',
  'platform.toast.deletionScheduled',
  'platform.toast.deletionCancelled',
  'platform.toast.residencyOn',
  'platform.toast.residencyOff',
  'platform.toast.userDeactivated',
  'platform.toast.userReactivated',
  'platform.toast.passwordResetSent',
  'platform.toast.invitationSent',
  'platform.toast.defaultsSaved',
];

/** Every key #168 adds (all plain strings). */
const NEW_KEYS: readonly string[] = [
  ...TAB_KEYS,
  ...ORG_STATUS_KEYS,
  ...USER_STATUS_KEYS,
  SEATS_KEY,
  ...FORM_ERROR_KEYS,
  ...ERROR_KEYS,
  ...ORG_CONFIRM_KEYS,
  ...USER_CONFIRM_KEYS,
  ...DEFAULTS_ERROR_KEYS,
  ...TOAST_KEYS,
];

/** Existing #242 keys the Defaults tab uses unchanged (presence check only). */
const KEPT_KEYS: readonly string[] = [
  'platform.defaults.residencyConfirm.title',
  'platform.defaults.residencyConfirm.body',
  'platform.defaults.residencyConfirm.confirm',
];

/** Every error text the console shows in place of a backend answer. */
const ALL_ERROR_KEYS: readonly string[] = [...ERROR_KEYS, ...FORM_ERROR_KEYS, ...DEFAULTS_ERROR_KEYS];

/** The only new keys with placeholders (sorted names); every other new key has none. */
const PLACEHOLDERS: Readonly<Record<string, readonly string[]>> = {
  [SEATS_KEY]: ['limit', 'used'],
  'platform.defaults.error.range': ['max', 'min'],
  ...Object.fromEntries(ORG_CONFIRM_KINDS.map((kind) => [`platform.orgs.confirm.${kind}.heading`, ['name']])),
  ...Object.fromEntries(USER_CONFIRM_KINDS.map((kind) => [`platform.users.confirm.${kind}.heading`, ['name']])),
};

/** Sample params for every placeholder a new key has (numbers small enough to never be grouped). */
const SAMPLE_PARAMS = { used: 3, limit: 10, name: 'Muster AG', min: 7, max: 90 };

/** The groups whose texts must be distinct within each locale. */
const DISTINCT_GROUPS: ReadonlyArray<[string, readonly string[]]> = [
  ['platform errors', ERROR_KEYS],
  ['org form errors', FORM_ERROR_KEYS],
  ['defaults errors', DEFAULTS_ERROR_KEYS],
  ['org confirm copy', ORG_CONFIRM_KEYS],
  ['user confirm copy', USER_CONFIRM_KEYS],
  ['toasts', TOAST_KEYS],
  ['org status labels', ORG_STATUS_KEYS],
  ['user status labels', USER_STATUS_KEYS],
  ['tabs', TAB_KEYS],
];

/** Patterns that mark an echoed backend answer or a server internal in an error text. */
const RAW_TEXT_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['HTTP', /\bhttps?\b/i],
  // An HTTP error status (4xx/5xx), e.g. "409"; a legitimate limit such as
  // "1 to 120 characters" is not one.
  ['an HTTP status code', /\b[45]\d\d\b/],
  ['braces', /[{}]/],
  ['a snake_case identifier', /\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b/],
];

/** The catalog's own string for `key`, or undefined. */
function textOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** True when the catalog has its own non-blank string for `key`. */
function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = textOf(catalog, key);
  return value !== undefined && value.trim() !== '';
}

/** Sorted placeholder names of a catalog value (`null` when the key has no string). */
function placeholdersOf(catalog: Record<string, unknown>, key: string): string[] | null {
  const value = textOf(catalog, key);
  if (value === undefined) return null;
  return [...new Set([...value.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
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

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

describe('i18n platform console keys added by issue #168', () => {
  it.each(LOCALES)('gives every new key its own non-blank %s entry and keeps the #242 residency keys', (target) => {
    const catalog = CATALOGS[target];

    expect({
      missingNew: NEW_KEYS.filter((key) => !hasText(catalog, key)),
      missingKept: KEPT_KEYS.filter((key) => !Object.hasOwn(catalog, key)),
    }).toEqual({ missingNew: [], missingKept: [] });
  });

  it.each(TRANSLATIONS)('%s translates every new key (its text differs from the en text)', (target) => {
    const untranslated = NEW_KEYS.filter((key) => {
      const source = textOf(en, key);
      const translated = textOf(CATALOGS[target], key);
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

  it.each(TRANSLATIONS)('t resolves every new key under %s to that locale\'s own text, never the raw key', (target) => {
    setLocale(target);

    const wrong = NEW_KEYS.filter((key) => {
      const own = textOf(CATALOGS[target], key);
      const text = t(key as MessageKey);
      return own === undefined || text === key || text.trim() === '' || text !== own;
    });

    expect(wrong).toEqual([]);
  });

  it.each(LOCALES)('%s uses exactly the contract placeholders for every new key', (target) => {
    const actual = Object.fromEntries(NEW_KEYS.map((key) => [key, placeholdersOf(CATALOGS[target], key)]));
    const wanted = Object.fromEntries(NEW_KEYS.map((key) => [key, [...(PLACEHOLDERS[key] ?? [])]]));

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

  it.each(LOCALES)('%s seat text shows the used and the limit counts', (target) => {
    setLocale(target);

    const text = t(SEATS_KEY as MessageKey, { used: 3, limit: 10 });

    expect({
      resolved: text !== SEATS_KEY,
      used: /(?<!\d)3(?!\d)/.test(text),
      limit: /(?<!\d)10(?!\d)/.test(text),
    }).toEqual({ resolved: true, used: true, limit: true });
  });

  it.each(LOCALES)('%s confirm headings name the organization or user', (target) => {
    setLocale(target);
    const headings = [
      ...ORG_CONFIRM_KINDS.map((kind) => `platform.orgs.confirm.${kind}.heading`),
      ...USER_CONFIRM_KINDS.map((kind) => `platform.users.confirm.${kind}.heading`),
    ];

    const unnamed = headings.filter((key) => {
      const text = t(key as MessageKey, { name: 'Zoë Muster' });
      return text === key || !text.includes('Zoë Muster');
    });

    expect(unnamed).toEqual([]);
  });

  it.each(LOCALES)('%s range error shows both bounds', (target) => {
    setLocale(target);
    const key = 'platform.defaults.error.range';

    const text = t(key as MessageKey, { min: 7, max: 90 });

    expect({
      resolved: text !== key,
      min: /(?<!\d)7(?!\d)/.test(text),
      max: /(?<!\d)90(?!\d)/.test(text),
    }).toEqual({ resolved: true, min: true, max: true });
  });
});

describe('i18n platform console groups are distinct (issue #168)', () => {
  const cases = LOCALES.flatMap((target) =>
    DISTINCT_GROUPS.map(([group, keys]) => ({ target, group, keys })),
  );

  it.each(cases)('the $group texts are distinct in $target', ({ target, keys }) => {
    const values = keys.map((key) => textOf(CATALOGS[target], key));

    expect({
      allText: values.every((value) => typeof value === 'string' && value.trim() !== ''),
      distinct: new Set(values.map((value) => value?.trim())).size,
    }).toEqual({ allText: true, distinct: keys.length });
  });
});

describe('i18n platform console error texts never look like a backend answer (issue #168)', () => {
  it.each(LOCALES)('%s error texts contain no HTTP, status code, stray brace or snake_case identifier', (target) => {
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
      // stray braces, but not a legitimate limit such as 120 characters.
      detector: {
        statusLine: rawTextHits('HTTP 409 Conflict'),
        bareStatus: rawTextHits('Request failed (422).'),
        sentenceEndStatus: rawTextHits('Error 409.'),
        reasonCode: rawTextHits('Refused: residency_confirmation'),
        braces: rawTextHits('Invalid {detail}'),
        lengthLimit: rawTextHits('Enter a name of 1 to 120 characters.'),
        bigNumber: rawTextHits('Enter a number from 0 to 8388607.'),
        placeholdersStripped: withoutListedPlaceholders('platform.defaults.error.range', 'From {min} to {max}.'),
      },
      offenders,
    }).toEqual({
      detector: {
        statusLine: ['HTTP', 'an HTTP status code'],
        bareStatus: ['an HTTP status code'],
        sentenceEndStatus: ['an HTTP status code'],
        reasonCode: ['a snake_case identifier'],
        braces: ['braces'],
        lengthLimit: [],
        bigNumber: [],
        placeholdersStripped: 'From   to  .',
      },
      offenders: {},
    });
  });
});
