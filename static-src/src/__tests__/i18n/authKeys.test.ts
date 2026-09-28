/**
 * Catalog keys for the auth pages and the role-aware shell (issue #155; all
 * UI strings go through the i18n catalogs with en/de/fr entries, #139 §5).
 *
 * Every key the new nav entries, the session-expired toast, the password
 * policy and the auth flows use must exist in the `en` source catalog and be
 * translated in `de` and `fr` (never falling back to English or to the raw
 * key). Key-set and placeholder parity between the catalogs is already
 * enforced by `catalogs.test.ts` and `npm run check:i18n`.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

const AUTH_KEYS: readonly string[] = [
  'nav.organization',
  'nav.platform',
  'nav.logout',
  'auth.sessionExpired.title',
  'auth.sessionExpired.body',
  'auth.login.error.invalid',
  'auth.error.rateLimited',
  'auth.error.generic',
  'auth.reset.error.invalidLink',
  'auth.invitation.error.invalidLink',
  'auth.invitation.error.invalidName',
  'auth.password.error.tooShort',
  'auth.password.error.tooLong',
  'auth.password.error.common',
  'auth.password.error.equalsEmail',
  'auth.password.error.mismatch',
  'auth.password.error.generic',
  'auth.password.rule.length',
  'auth.password.rule.common',
  'auth.password.rule.email',
];

const TRANSLATIONS: Record<'de' | 'fr', Record<string, unknown>> = { de, fr };

afterEach(() => {
  setLocale('en');
});

describe('i18n auth keys', () => {
  it('defines every auth and shell key in the en source catalog', () => {
    expect(AUTH_KEYS.filter((key) => !Object.hasOwn(en, key))).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('gives every auth and shell key its own %s entry', (target) => {
    expect(AUTH_KEYS.filter((key) => !Object.hasOwn(TRANSLATIONS[target], key))).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('resolves every auth and shell key under %s to a translation', (target) => {
    setLocale(target);

    const unresolved = AUTH_KEYS.filter((key) => {
      const text = t(key as MessageKey, { min: 12, max: 128 });
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it('gives the session-expired toast a title and a body in en', () => {
    setLocale('en');

    const texts = [t('auth.sessionExpired.title' as MessageKey), t('auth.sessionExpired.body' as MessageKey)];

    expect(texts.filter((text) => text.startsWith('auth.') || text.trim() === '')).toEqual([]);
  });
});
