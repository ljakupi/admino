/**
 * i18n app singleton and catalog tests (issue #144: PWA internationalization).
 *
 * `@/i18n` exports the app-wide instance built from the real catalogs
 * (`en` is the source, `de` and `fr` translate it) plus its bound members
 * (`t`, `setLocale`, `formatDate`, `formatNumber`, `formatChf`, `locale`) and
 * `useI18n()`, which returns the same singleton. It starts in `en`, so the UI
 * reads as before until #166 wires the user's `ui_language`.
 *
 * The catalog checks are the runtime twin of `npm run check:i18n`: identical
 * key sets, identical `{placeholder}` names per key (plural messages: the
 * union over all forms), well-formed plural messages (an `other` form, valid
 * LDML categories only) and no empty values. Failures list the offending
 * keys so a missing translation is easy to find. No component is mounted.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import {
  formatChf,
  formatDate,
  formatNumber,
  i18n,
  locale,
  segments,
  setLocale,
  t,
  useI18n,
  type MessageKey,
} from '@/i18n';
import type { Locale } from '@/i18n/core';

const CATALOGS: Record<Locale, Record<string, unknown>> = { en, de, fr };
const TRANSLATIONS: readonly Locale[] = ['de', 'fr'];
const PLURAL_CATEGORIES = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** Noon UTC, so the calendar date is the same in every realistic time zone. */
const NOON_UTC = new Date(Date.UTC(2026, 2, 5, 12));

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Every string form of a catalog value (one for a string, one per plural form). */
function formsOf(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (isPlainObject(value)) return Object.values(value).filter((v): v is string => typeof v === 'string');
  return [];
}

/** Sorted placeholder names used by a catalog value (union over plural forms). */
function placeholdersOf(value: unknown): string[] {
  const names = new Set<string>();
  for (const form of formsOf(value)) {
    for (const match of form.matchAll(PLACEHOLDER)) names.add(match[1]);
  }
  return [...names].sort();
}

function keyDiff(locale: Locale): { missing: string[]; extra: string[] } {
  const catalog = CATALOGS[locale];
  return {
    missing: Object.keys(en)
      .filter((key) => !Object.hasOwn(catalog, key))
      .sort(),
    extra: Object.keys(catalog)
      .filter((key) => !Object.hasOwn(en, key))
      .sort(),
  };
}

/** ICU uses (narrow) no-break spaces; compare them as plain spaces. */
function plain(text: string): string {
  return text.replace(/[  ]/g, ' ');
}

const EN_KEYS = Object.keys(en) as MessageKey[];

afterEach(() => {
  setLocale('en');
  document.documentElement.removeAttribute('lang');
});

// --- The singleton --------------------------------------------------------

describe('i18n singleton', () => {
  it('starts in en', async () => {
    vi.resetModules();
    const fresh = await import('@/i18n');

    expect([fresh.locale.value, fresh.i18n.locale.value]).toEqual(['en', 'en']);
  });

  it('useI18n returns the singleton', () => {
    expect(useI18n()).toBe(i18n);
  });

  it('useI18n().setLocale switches the t exported from @/i18n', () => {
    const key = EN_KEYS.find((k) => typeof de[k] === 'string' && de[k] !== en[k]);
    if (key === undefined) throw new Error('test setup: expected a translated de string');

    useI18n().setLocale('de');

    expect([locale.value, t(key)]).toEqual(['de', de[key]]);
  });

  it('the exported segments follows the singleton locale', () => {
    const key = EN_KEYS.find((k) => {
      const value = de[k];
      return typeof value === 'string' && value !== en[k] && !value.includes('{');
    });
    if (key === undefined) throw new Error('test setup: expected a translated de string without placeholders');

    setLocale('de');

    expect(segments(key)).toEqual([{ kind: 'text', text: de[key] }]);
  });

  it('the exported setLocale switches the singleton', () => {
    const applied = setLocale('FR');

    expect([applied, i18n.locale.value, locale.value]).toEqual(['fr', 'fr', 'fr']);
  });

  it('the exported formatters follow the singleton locale', () => {
    useI18n().setLocale('fr');

    expect([
      plain(formatChf(1234.5)),
      plain(formatNumber(1234567.891)),
      plain(formatDate(NOON_UTC, { dateStyle: 'medium', timeZone: 'UTC' })),
    ]).toEqual(['1 234.50 CHF', '1 234 567,891', '5 mars 2026']);
  });

  it.each<Locale>(['en', 'de', 'fr'])('t reads every string key from the %s catalog', (target) => {
    setLocale(target);
    const catalog = CATALOGS[target];
    const stringKeys = EN_KEYS.filter((key) => typeof catalog[key] === 'string');

    const wrong = stringKeys.filter((key) => t(key) !== catalog[key]);

    expect(stringKeys.length).toBeGreaterThan(0);
    expect(wrong).toEqual([]);
  });
});

// --- Catalog parity -------------------------------------------------------

describe('i18n catalogs', () => {
  it('en, the source catalog, is not empty', () => {
    expect(EN_KEYS.length).toBeGreaterThan(0);
  });

  it('de and fr have exactly the key set of en', () => {
    expect({ de: keyDiff('de'), fr: keyDiff('fr') }).toEqual({
      de: { missing: [], extra: [] },
      fr: { missing: [], extra: [] },
    });
  });

  it('uses the same placeholders for every key in every locale', () => {
    const mismatches = EN_KEYS.flatMap((key) => {
      const [enNames, deNames, frNames] = (['en', 'de', 'fr'] as const).map((l) =>
        placeholdersOf(CATALOGS[l][key]).join(','),
      );
      return enNames === deNames && enNames === frNames
        ? []
        : [{ key, en: enNames, de: deNames, fr: frNames }];
    });

    expect(mismatches).toEqual([]);
  });

  it('gives every plural message an other form and only valid LDML categories', () => {
    const problems = (['en', 'de', 'fr'] as const).flatMap((l) =>
      Object.entries(CATALOGS[l]).flatMap(([key, value]) => {
        if (typeof value === 'string') return [];
        if (!isPlainObject(value)) return [`${l}: ${key} is neither a string nor a plural object`];
        const issues: string[] = [];
        if (typeof value.other !== 'string') issues.push(`${l}: ${key} has no other form`);
        for (const [category, form] of Object.entries(value)) {
          if (!PLURAL_CATEGORIES.has(category)) issues.push(`${l}: ${key} has category ${category}`);
          if (typeof form !== 'string') issues.push(`${l}: ${key}.${category} is not a string`);
        }
        return issues;
      }),
    );

    expect(problems).toEqual([]);
  });

  it('has no empty or blank value in any locale', () => {
    const blank = (['en', 'de', 'fr'] as const).flatMap((l) =>
      Object.entries(CATALOGS[l]).flatMap(([key, value]) => {
        const forms = formsOf(value);
        return forms.length === 0 || forms.some((form) => form.trim() === '') ? [`${l}: ${key}`] : [];
      }),
    );

    expect(blank).toEqual([]);
  });

  it.each(TRANSLATIONS)('%s is a translation, not a copy of en', (target) => {
    const translated = EN_KEYS.filter(
      (key) => JSON.stringify(CATALOGS[target][key]) !== JSON.stringify(en[key]),
    );

    expect(translated.length).toBeGreaterThan(0);
  });
});
