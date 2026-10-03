/**
 * Catalog keys for the My account section of Settings (issue #166: account
 * self-service; all strings go through the i18n catalogs with en/de/fr
 * entries, #139 §5).
 *
 * Every key the account section (profile, languages, timezone, personal
 * instructions, password change, session list), its errors and its toasts
 * use must exist in the `en` source catalog with a non-blank value and have
 * its own non-blank `de` and `fr` entry. The placeholders are exactly the
 * contract's: `account.instructions.remaining` {count},
 * `account.sessions.lastSeen` {date}, `account.sessions.ip` {ip},
 * `account.sessions.device` {browser} {os}, `account.error.nameTooLong` and
 * `account.error.instructionsTooLong` {max}; every other new key has none.
 *
 * A de/fr value never equals the en value (no English fallback), except the
 * four language names `account.language.de|fr|it|en`, which are each
 * language's own name ("Deutsch", "Français", "Italiano", "English") and
 * identical in all three catalogs. Pinned en texts: `settings.nav.account`
 * "My account", `account.profile.email.hint` "Ask an Org Admin to change
 * your email.", `account.languages.response.orgDefault` "Organization
 * default", and `account.instructions.hint` exactly "Your name and role,
 * your company, the tone you want, how to sign off".
 *
 * The key list is pinned from the GH-166 contract (§2.8) rather than read
 * from `@/services/account`, so this file runs on its own;
 * `services/account.test.ts` cross-checks the keys its mappers return.
 * Key-set and placeholder parity between catalogs is also enforced by
 * `catalogs.test.ts` and `npm run check:i18n`. No component is mounted.
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

const NAV_KEYS: readonly string[] = ['settings.nav.account'];

const PROFILE_KEYS: readonly string[] = [
  'account.title',
  'account.subtitle',
  'account.profile.title',
  'account.profile.name.label',
  'account.profile.email.label',
  'account.profile.email.hint',
  'account.profile.save',
];

/** Each language's own name: identical in en, de and fr. */
const LANGUAGE_NAMES: Readonly<Record<string, string>> = {
  'account.language.de': 'Deutsch',
  'account.language.fr': 'Français',
  'account.language.it': 'Italiano',
  'account.language.en': 'English',
};

const LANGUAGE_KEYS: readonly string[] = [
  'account.languages.title',
  'account.languages.ui.label',
  'account.languages.ui.hint',
  'account.languages.response.label',
  'account.languages.response.hint',
  'account.languages.response.orgDefault',
  ...Object.keys(LANGUAGE_NAMES),
];

const TIMEZONE_KEYS: readonly string[] = ['account.timezone.label', 'account.timezone.hint'];

const INSTRUCTION_KEYS: readonly string[] = [
  'account.instructions.label',
  'account.instructions.hint',
  'account.instructions.remaining',
  'account.instructions.placeholder',
];

const PASSWORD_KEYS: readonly string[] = [
  'account.password.title',
  'account.password.subtitle',
  'account.password.current',
  'account.password.new',
  'account.password.confirm',
  'account.password.submit',
  'account.password.notice',
  'account.password.error.current',
  'account.password.error.currentRequired',
  'account.toast.passwordChanged',
];

const SESSION_KEYS: readonly string[] = [
  'account.sessions.title',
  'account.sessions.subtitle',
  'account.sessions.current',
  'account.sessions.lastSeen',
  'account.sessions.ip',
  'account.sessions.ipUnknown',
  'account.sessions.device',
  'account.sessions.unknownDevice',
  'account.sessions.revoke',
  'account.sessions.revokeConfirm.heading',
  'account.sessions.revokeConfirm.subtext',
  'account.sessions.revokeConfirm.confirm',
  'account.sessions.empty',
  'account.sessions.error.load',
  'account.sessions.error.revoke',
];

const ERROR_AND_TOAST_KEYS: readonly string[] = [
  'account.error.load',
  'account.error.generic',
  'account.error.invalid',
  'account.error.nameRequired',
  'account.error.nameTooLong',
  'account.error.instructionsTooLong',
  'account.toast.saved',
];

const NEW_KEYS: readonly string[] = [
  ...NAV_KEYS,
  ...PROFILE_KEYS,
  ...LANGUAGE_KEYS,
  ...TIMEZONE_KEYS,
  ...INSTRUCTION_KEYS,
  ...PASSWORD_KEYS,
  ...SESSION_KEYS,
  ...ERROR_AND_TOAST_KEYS,
];

/** The only new keys with placeholders (sorted names); every other new key has none. */
const PLACEHOLDERS: Readonly<Record<string, readonly string[]>> = {
  'account.instructions.remaining': ['count'],
  'account.sessions.lastSeen': ['date'],
  'account.sessions.ip': ['ip'],
  'account.sessions.device': ['browser', 'os'],
  'account.error.nameTooLong': ['max'],
  'account.error.instructionsTooLong': ['max'],
};

/** The en texts the contract quotes verbatim. */
const PINNED_EN: Readonly<Record<string, string>> = {
  'settings.nav.account': 'My account',
  'account.profile.email.hint': 'Ask an Org Admin to change your email.',
  'account.languages.response.orgDefault': 'Organization default',
  'account.instructions.hint': 'Your name and role, your company, the tone you want, how to sign off',
};

/** True when the catalog has its own non-blank string for `key`. */
function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' && value.trim() !== '';
}

/** The catalog's own string for `key`, or undefined. */
function textOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** Sorted placeholder names of a catalog value (`null` when the key has no string). */
function placeholdersOf(catalog: Record<string, unknown>, key: string): string[] | null {
  const value = textOf(catalog, key);
  if (value === undefined) return null;
  return [...new Set([...value.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

describe('i18n account keys added by issue #166', () => {
  it.each(LOCALES)('gives every one of the 56 new keys its own non-blank %s entry', (target) => {
    expect({
      listed: new Set(NEW_KEYS).size,
      missing: NEW_KEYS.filter((key) => !hasText(CATALOGS[target], key)),
    }).toEqual({ listed: 56, missing: [] });
  });

  it.each(LOCALES)('resolves every new key under %s to text, never the raw key', (target) => {
    setLocale(target);

    const unresolved = NEW_KEYS.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it.each(LOCALES)('%s uses exactly the contract placeholders for every new key', (target) => {
    const actual = Object.fromEntries(NEW_KEYS.map((key) => [key, placeholdersOf(CATALOGS[target], key)]));
    const wanted = Object.fromEntries(NEW_KEYS.map((key) => [key, [...(PLACEHOLDERS[key] ?? [])]]));

    expect(actual).toEqual(wanted);
  });

  it.each(TRANSLATIONS)('%s translates every new key except the language names (no English fallback)', (target) => {
    const catalog = CATALOGS[target];
    const untranslated = NEW_KEYS.filter((key) => {
      if (Object.hasOwn(LANGUAGE_NAMES, key)) return false;
      const source = textOf(en, key);
      const translated = textOf(catalog, key);
      if (source === undefined || translated === undefined || source.trim() === '' || translated.trim() === '') {
        return true;
      }
      return translated.trim() === source.trim();
    });

    expect(untranslated).toEqual([]);
  });

  it.each(LOCALES)('%s names each language in that language (identical in every catalog)', (target) => {
    const names = Object.fromEntries(Object.keys(LANGUAGE_NAMES).map((key) => [key, textOf(CATALOGS[target], key)]));

    expect(names).toEqual(LANGUAGE_NAMES);
  });

  it.each(Object.entries(PINNED_EN))('the en text of %s is %j', (key, text) => {
    expect(textOf(en, key)).toBe(text);
  });

  it.each(LOCALES)('%s fills the browser and the OS into the device line', (target) => {
    setLocale(target);

    const text = t('account.sessions.device' as MessageKey, { browser: 'Firefox', os: 'Linux' });

    expect({ browser: text.includes('Firefox'), os: text.includes('Linux'), raw: /\{(browser|os)\}/.test(text) }).toEqual({
      browser: true,
      os: true,
      raw: false,
    });
  });

  it.each(LOCALES)('%s fills the limit into both too-long messages', (target) => {
    setLocale(target);

    const texts = ['account.error.nameTooLong', 'account.error.instructionsTooLong'].map((key) =>
      t(key as MessageKey, { max: 1500 }),
    );

    expect(texts.map((text) => text.includes('1500') && !text.includes('{max}'))).toEqual([true, true]);
  });
});
