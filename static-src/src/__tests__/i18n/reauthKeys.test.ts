/**
 * Catalog keys for the password re-auth prompt (issue #161: promoting a
 * critical permission needs the Org Admin's password; all UI strings go
 * through the i18n catalogs with en/de/fr entries, #139 §5).
 *
 * Added: `reauth.title`, `reauth.body` (with the `{action}` and `{tool}`
 * placeholders), `reauth.passwordLabel`, `reauth.submit`,
 * `reauth.error.wrongPassword` (a refused re-auth, 403) and
 * `reauth.error.failed` (any other failure). Each must exist in the `en`
 * source catalog with a non-blank value and have its own non-blank `de` and
 * `fr` entry (never falling back to English or to the raw key). The two
 * error messages must differ, so the store's 403 / other-error split is
 * visible to the user. Key-set and placeholder parity between the catalogs
 * is also enforced by `catalogs.test.ts` and `npm run check:i18n`. No
 * component is mounted.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];

const REAUTH_KEYS: readonly string[] = [
  'reauth.title',
  'reauth.body',
  'reauth.passwordLabel',
  'reauth.submit',
  'reauth.error.wrongPassword',
  'reauth.error.failed',
];

/** The catalog's own string for `key`, or undefined. */
function ownText(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

afterEach(() => {
  setLocale('en');
});

describe('i18n re-auth keys added by issue #161', () => {
  it.each(LOCALES)('gives every re-auth key its own non-blank %s string', (target) => {
    expect(REAUTH_KEYS.filter((key) => (ownText(CATALOGS[target], key) ?? '').trim() === '')).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('resolves every re-auth key under %s to a translation, not the key', (target) => {
    setLocale(target);

    const unresolved = REAUTH_KEYS.filter((key) => {
      const text = t(key as MessageKey, { action: 'x', tool: 'y' });
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it.each(LOCALES)('uses the {action} and {tool} placeholders in reauth.body under %s', (target) => {
    const body = ownText(CATALOGS[target], 'reauth.body') ?? '';

    expect({ action: body.includes('{action}'), tool: body.includes('{tool}') }).toEqual({
      action: true,
      tool: true,
    });
  });

  it.each(LOCALES)('fills both placeholders of reauth.body under %s', (target) => {
    setLocale(target);

    const text = t('reauth.body' as MessageKey, { action: 'ACTION_MARK', tool: 'TOOL_MARK' });

    expect({
      action: text.includes('ACTION_MARK'),
      tool: text.includes('TOOL_MARK'),
      leftover: /\{(action|tool)\}/.test(text),
    }).toEqual({ action: true, tool: true, leftover: false });
  });

  it.each(LOCALES)('keeps the wrong-password and the generic failure messages distinct under %s', (target) => {
    const wrong = ownText(CATALOGS[target], 'reauth.error.wrongPassword');
    const failed = ownText(CATALOGS[target], 'reauth.error.failed');

    expect({ bothSet: wrong !== undefined && failed !== undefined, distinct: wrong !== failed }).toEqual({
      bothSet: true,
      distinct: true,
    });
  });
});
