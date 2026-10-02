/**
 * Catalog keys for "my connections" and the Organization console's services
 * (issue #162: the Tools page becomes "my connections"; the Org Admin's
 * service switches move to the Organization console; residency orgs see the
 * Google/Microsoft rows disabled with a short explanation; all UI strings go
 * through the i18n catalogs with en/de/fr entries, #139 §5).
 *
 * Every key the GH-162 logic can resolve must exist in the `en` source
 * catalog with a non-blank value and have its own non-blank `de` and `fr`
 * entry (never falling back to English or to the raw key):
 * - every key `serviceStateKey` returns (`toolsPage.service.state.active`,
 *   `.orgDisabled`, `.residency`, `.notConnected`),
 * - every key `oauthCallbackMessageKey` returns (`toolsPage.oauth.reason.*`
 *   for denied, invalidState, missingCode, exchangeFailed, forbidden,
 *   residency and the `unexpected` fallback),
 * - the residency copy (`toolsPage.residency.explanation`,
 *   `toolsPage.residency.connectBlocked`) and the Organization console's
 *   services card (`organization.services.title`, `.subtitle`,
 *   `.residencyLocked`),
 * - the toast titles and fallback bodies the connections and org-services
 *   stores show.
 * The seven callback messages and the four service-state labels must be
 * distinct within each locale, so the user can tell the outcomes apart.
 *
 * The key lists are pinned from the GH-162 contract (§14) rather than read
 * from `@/services/connections`, so this file runs on its own;
 * `services/connections.test.ts` cross-checks the keys the functions return.
 * Key-set and placeholder parity between the catalogs is also enforced by
 * `catalogs.test.ts` and `npm run check:i18n`. No component is mounted.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { setLocale, t, type MessageKey } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];

/** Every key `serviceStateKey` can return. */
const SERVICE_STATE_KEYS: readonly string[] = [
  'toolsPage.service.state.active',
  'toolsPage.service.state.orgDisabled',
  'toolsPage.service.state.residency',
  'toolsPage.service.state.notConnected',
];

/** Every key `oauthCallbackMessageKey` can return. */
const CALLBACK_REASON_KEYS: readonly string[] = [
  'toolsPage.oauth.reason.denied',
  'toolsPage.oauth.reason.invalidState',
  'toolsPage.oauth.reason.missingCode',
  'toolsPage.oauth.reason.exchangeFailed',
  'toolsPage.oauth.reason.forbidden',
  'toolsPage.oauth.reason.residency',
  'toolsPage.oauth.reason.unexpected',
];

/** The residency explanation and the Organization console's services card. */
const RESIDENCY_AND_SERVICES_KEYS: readonly string[] = [
  'toolsPage.residency.explanation',
  'toolsPage.residency.connectBlocked',
  'organization.services.title',
  'organization.services.subtitle',
  'organization.services.residencyLocked',
];

/** Toast titles and fallback bodies of the connections and org-services stores. */
const STORE_TOAST_KEYS: readonly string[] = [
  'toast.settings.connectionFailed.title',
  'toast.settings.googleDisconnected',
  'toast.settings.microsoftDisconnected',
  'toast.settings.disconnectFailed.title',
  'toast.common.saved',
  'toast.common.saveFailed.title',
  'settings.error.unexpectedRedirect',
  'settings.error.oauthStartFailed',
  'settings.error.disconnectFailed',
  'settings.error.saveFailed',
];

const ALL_KEYS: readonly string[] = [
  ...SERVICE_STATE_KEYS,
  ...CALLBACK_REASON_KEYS,
  ...RESIDENCY_AND_SERVICES_KEYS,
  ...STORE_TOAST_KEYS,
];

/** The catalog's own string for `key`, or undefined. */
function ownText(catalog: Record<string, unknown>, key: string): string | undefined {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** The keys of `keys` without their own non-blank string in `catalog`. */
function missingIn(catalog: Record<string, unknown>, keys: readonly string[]): string[] {
  return keys.filter((key) => (ownText(catalog, key) ?? '').trim() === '');
}

afterEach(() => {
  setLocale('en');
});

describe('i18n connections keys used by issue #162', () => {
  it.each(LOCALES)('gives every service-state key its own non-blank %s string', (locale) => {
    expect(missingIn(CATALOGS[locale], SERVICE_STATE_KEYS)).toEqual([]);
  });

  it.each(LOCALES)('gives every OAuth callback reason key its own non-blank %s string', (locale) => {
    expect(missingIn(CATALOGS[locale], CALLBACK_REASON_KEYS)).toEqual([]);
  });

  it.each(LOCALES)('gives the residency and Organization services keys their own non-blank %s string', (locale) => {
    expect(missingIn(CATALOGS[locale], RESIDENCY_AND_SERVICES_KEYS)).toEqual([]);
  });

  it.each(LOCALES)('gives every issue #162 key, toasts included, its own non-blank %s string', (locale) => {
    expect(missingIn(CATALOGS[locale], ALL_KEYS)).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('resolves every issue #162 key under %s to a translation, not the key', (locale) => {
    setLocale(locale);

    const unresolved = ALL_KEYS.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });

  it.each(LOCALES)('keeps the seven OAuth callback messages distinct under %s', (locale) => {
    const texts = CALLBACK_REASON_KEYS.map((key) => ownText(CATALOGS[locale], key));

    expect({
      allSet: texts.every((text) => text !== undefined),
      distinct: new Set(texts).size,
    }).toEqual({ allSet: true, distinct: CALLBACK_REASON_KEYS.length });
  });

  it.each(LOCALES)('keeps the four service-state labels distinct under %s', (locale) => {
    const texts = SERVICE_STATE_KEYS.map((key) => ownText(CATALOGS[locale], key));

    expect({
      allSet: texts.every((text) => text !== undefined),
      distinct: new Set(texts).size,
    }).toEqual({ allSet: true, distinct: SERVICE_STATE_KEYS.length });
  });
});
