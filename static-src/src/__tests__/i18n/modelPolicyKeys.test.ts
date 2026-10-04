/**
 * Catalog keys for the V1 model policy (issue #242; decisions D1 and D3; all
 * UI strings go through the i18n catalogs with en/de/fr entries, #139 §5).
 *
 * Added:
 * - The chat error texts (D3): `chat.error.<code>` for the seven LLM error
 *   codes (not_configured, missing_model, provider_unavailable,
 *   rate_limited, timeout, residency_blocked, context_too_long) and
 *   `chat.error.generic` for an error reply without a known code. The chat
 *   store shows them with `t(key)` and no params, so they have no
 *   placeholder. They are what the user reads instead of the backend's
 *   English `response`, so none of them names server internals or looks
 *   like raw provider output: no "HTTP", no HTTP status code, no env var
 *   name (INFOMANIAK_API_TOKEN, ...), no snake_case identifier, no config
 *   file, no braces. The eight texts are distinct within each locale, so the
 *   user can tell the outcomes apart.
 * - The residency confirmation copy (D1; #168 renders the dialog):
 *   `platform.defaults.residencyConfirm.title`, `.confirm`, and `.body` — a
 *   plural message with `one` and `other` forms, each holding the `{count}`
 *   placeholder and no other one, in all three locales. (`{count}` is needed
 *   in the `one` form too: French uses `one` for 0 and 1, and a count of 0
 *   is a valid confirmation.)
 *
 * Every new key has its own non-blank en, de and fr entry; every de/fr text
 * differs from the en text (no English fallback), and `t` resolves it under
 * de/fr to a translation, never the raw key.
 *
 * The key lists are pinned from the GH-242 contract (§6) rather than read
 * from `@/services/chatErrors`, so this file runs on its own;
 * `services/chatErrors.test.ts` cross-checks the keys the function returns.
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

const CHAT_ERROR_KEYS: readonly string[] = [
  'chat.error.not_configured',
  'chat.error.missing_model',
  'chat.error.provider_unavailable',
  'chat.error.rate_limited',
  'chat.error.timeout',
  'chat.error.residency_blocked',
  'chat.error.context_too_long',
  'chat.error.generic',
];

const CONFIRM_STRING_KEYS: readonly string[] = [
  'platform.defaults.residencyConfirm.title',
  'platform.defaults.residencyConfirm.confirm',
];

const BODY_KEY = 'platform.defaults.residencyConfirm.body';

/** Every new plain-string key (the body is a plural message). */
const STRING_KEYS: readonly string[] = [...CHAT_ERROR_KEYS, ...CONFIRM_STRING_KEYS];

/** Patterns that mark raw provider output or server internals in a user-facing text. */
const RAW_TEXT_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['HTTP', /\bhttps?\b/i],
  ['an HTTP status code', /\b[1-5]\d\d\b/],
  ['an env var name', /\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/],
  ['a snake_case identifier', /\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b/],
  ['a config file', /\.ya?ml\b|\.env\b/i],
  ['braces', /[{}]/],
  ['an exception class name', /\b\w+(?:Error|Exception)\b|\btraceback\b/i],
];

/** Known server-internal names that must never reach the chat text. */
const SERVER_NAMES: readonly string[] = [
  'INFOMANIAK_API_TOKEN',
  'INFOMANIAK_PRODUCT_ID',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'config.yaml',
  'LLMError',
];

/** The catalog's own string for `key`, or undefined. */
function textOf(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = textOf(catalog, key);
  return value !== undefined && value.trim() !== '';
}

/** The catalog's own plural object for `key`, or undefined. */
function pluralOf(catalog: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Sorted placeholder names in `text`. */
function placeholdersIn(text: string): string[] {
  return [...new Set([...text.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
}

/** Names of the raw-text patterns / server names `text` contains. */
function rawTextHits(text: string): string[] {
  return [
    ...RAW_TEXT_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name),
    ...SERVER_NAMES.filter((name) => text.includes(name)),
  ];
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

describe('i18n model policy keys added by issue #242', () => {
  it.each(LOCALES)('gives every new string key its own non-blank %s entry', (target) => {
    expect(STRING_KEYS.filter((key) => !hasText(CATALOGS[target], key))).toEqual([]);
  });

  it.each(TRANSLATIONS)('resolves every new string key under %s to a translation, not the key', (target) => {
    setLocale(target);

    const unresolved = STRING_KEYS.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it.each(TRANSLATIONS)('%s translates every new string key (no English fallback)', (target) => {
    const untranslated = STRING_KEYS.filter((key) => {
      const source = textOf(en, key);
      const translated = textOf(CATALOGS[target], key);
      return (
        source === undefined ||
        translated === undefined ||
        translated.trim() === '' ||
        translated.trim() === source.trim()
      );
    });

    expect(untranslated).toEqual([]);
  });
});

describe('i18n chat error texts (issue #242, D3)', () => {
  it.each(LOCALES)('%s chat error texts have no placeholder (the store passes no params)', (target) => {
    const withPlaceholders = CHAT_ERROR_KEYS.filter((key) => {
      const text = textOf(CATALOGS[target], key);
      return text === undefined || placeholdersIn(text).length > 0;
    });

    expect(withPlaceholders).toEqual([]);
  });

  it.each(LOCALES)('the eight chat error texts are distinct in %s', (target) => {
    const values = CHAT_ERROR_KEYS.map((key) => textOf(CATALOGS[target], key));

    expect({
      allText: values.every((value) => typeof value === 'string' && value.trim() !== ''),
      distinct: new Set(values.map((value) => value?.trim())).size,
    }).toEqual({ allText: true, distinct: CHAT_ERROR_KEYS.length });
  });

  it.each(LOCALES)('%s chat error texts name no server internals and look like no raw provider output', (target) => {
    const offenders = Object.fromEntries(
      CHAT_ERROR_KEYS.flatMap((key) => {
        const text = textOf(CATALOGS[target], key);
        if (text === undefined || text.trim() === '') return [[key, ['missing']]];
        const hits = rawTextHits(text);
        return hits.length > 0 ? [[key, hits]] : [];
      }),
    );

    expect({
      // Non-vacuity: the detector does flag provider-style and config-style text.
      detectsProviderText: rawTextHits('Infomaniak API returned HTTP 429').length > 0,
      detectsEnvVar: rawTextHits('Set INFOMANIAK_API_TOKEN in the environment.').length > 0,
      detectsSdkCode: rawTextHits('Error code: rate_limit_exceeded').length > 0,
      offenders,
    }).toEqual({ detectsProviderText: true, detectsEnvVar: true, detectsSdkCode: true, offenders: {} });
  });
});

describe('i18n residency confirmation copy (issue #242, D1)', () => {
  it.each(LOCALES)('%s body is a plural message with distinct one and other forms, each with only {count}', (target) => {
    const body = pluralOf(CATALOGS[target], BODY_KEY);
    const formOf = (category: string): string | undefined => {
      const value = body !== undefined && Object.hasOwn(body, category) ? body[category] : undefined;
      return typeof value === 'string' && value.trim() !== '' ? value : undefined;
    };
    const one = formOf('one');
    const other = formOf('other');

    expect({
      isPlural: body !== undefined,
      onePlaceholders: one === undefined ? null : placeholdersIn(one),
      otherPlaceholders: other === undefined ? null : placeholdersIn(other),
      formsDiffer: one !== undefined && other !== undefined && one.trim() !== other.trim(),
    }).toEqual({ isPlural: true, onePlaceholders: ['count'], otherPlaceholders: ['count'], formsDiffer: true });
  });

  it.each(TRANSLATIONS)('%s body forms differ from the en forms (no English fallback)', (target) => {
    const source = pluralOf(en, BODY_KEY);
    const translated = pluralOf(CATALOGS[target], BODY_KEY);
    const same = ['one', 'other'].filter((category) => {
      const a = source?.[category];
      const b = translated?.[category];
      return typeof a !== 'string' || typeof b !== 'string' || a.trim() === b.trim();
    });

    expect(same).toEqual([]);
  });

  it.each(LOCALES)('%s resolves the body with the count interpolated', (target) => {
    setLocale(target);

    const single = t(BODY_KEY as MessageKey, { count: 1 });
    const several = t(BODY_KEY as MessageKey, { count: 3 });

    expect({
      resolved: single !== BODY_KEY && several !== BODY_KEY,
      singleHasCount: single.includes('1') && !single.includes('{count}'),
      severalHasCount: several.includes('3') && !several.includes('{count}'),
    }).toEqual({ resolved: true, singleHasCount: true, severalHasCount: true });
  });

  it.each(TRANSLATIONS)('%s resolves the body to its own text, not the English one', (target) => {
    setLocale('en');
    const english = t(BODY_KEY as MessageKey, { count: 3 });
    setLocale(target);

    const translated = t(BODY_KEY as MessageKey, { count: 3 });

    expect({ resolved: translated !== BODY_KEY, differs: translated !== english }).toEqual({
      resolved: true,
      differs: true,
    });
  });

  it.each(LOCALES)('%s title and confirm label have no placeholder other than {count}', (target) => {
    const stray = CONFIRM_STRING_KEYS.filter((key) => {
      const text = textOf(CATALOGS[target], key);
      return text === undefined || placeholdersIn(text).some((name) => name !== 'count');
    });

    expect(stray).toEqual([]);
  });
});
