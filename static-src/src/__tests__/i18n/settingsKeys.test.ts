/**
 * Catalog keys for the Settings controls (issue #35: task-done pings, reset
 * my settings; all UI strings go through the i18n catalogs with en/de/fr
 * entries, #139 §5).
 *
 * Added: the reset toasts (`toast.settings.settingsReset`,
 * `toast.settings.resetFailed.title`), the reset fallback error
 * (`settings.error.resetFailed`) and the reset confirmation sheet copy
 * (`settings.danger.resetConfirm.heading|subtext|confirm`). Each must exist in
 * the `en` source catalog with a non-blank value and have its own non-blank
 * `de` and `fr` entry (never falling back to English or to the raw key).
 *
 * Removed (dead stubs, no leftover): the Sound toggle copy, the Clear
 * conversation / Disconnect all / Erase all data rows and the Clear confirm
 * sheet, the "Coming soon" toasts and the chat-cleared toast. No catalog may
 * keep any of those keys, nor any other key under their prefixes.
 * `settings.toast.newSession` stays (the Session section's "New session"
 * button still uses it; regression guard).
 *
 * Key-set and placeholder parity between the catalogs is already enforced by
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

const ADDED_KEYS: readonly string[] = [
  'toast.settings.settingsReset',
  'toast.settings.resetFailed.title',
  'settings.error.resetFailed',
  'settings.danger.resetConfirm.heading',
  'settings.danger.resetConfirm.subtext',
  'settings.danger.resetConfirm.confirm',
];

const REMOVED_KEYS: readonly string[] = [
  'settings.notifications.sound.label',
  'settings.notifications.sound.hint',
  'settings.danger.clear.label',
  'settings.danger.clear.hint',
  'settings.danger.clear.button',
  'settings.danger.disconnectAll.label',
  'settings.danger.disconnectAll.hint',
  'settings.danger.disconnectAll.button',
  'settings.danger.erase.label',
  'settings.danger.erase.hint',
  'settings.danger.erase.button',
  'settings.danger.clearConfirm.heading',
  'settings.danger.clearConfirm.subtext',
  'settings.danger.clearConfirm.confirm',
  'settings.comingSoon.title',
  'settings.comingSoon.resetSettings',
  'settings.comingSoon.eraseAll',
  'settings.comingSoon.toggle',
  'settings.toast.chatCleared',
];

/** Prefixes of the removed rows and stubs: no key may live under them any more. */
const REMOVED_PREFIXES: readonly string[] = [
  'settings.notifications.sound.',
  'settings.danger.clear.',
  'settings.danger.disconnectAll.',
  'settings.danger.erase.',
  'settings.danger.clearConfirm.',
  'settings.comingSoon.',
];

/** True when the catalog has its own non-blank string for `key`. */
function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' && value.trim() !== '';
}

afterEach(() => {
  setLocale('en');
});

describe('i18n settings keys added by issue #35', () => {
  it.each(LOCALES)('gives every new reset key its own non-blank %s entry', (target) => {
    expect(ADDED_KEYS.filter((key) => !hasText(CATALOGS[target], key))).toEqual([]);
  });

  it.each(['de', 'fr'] as const)('resolves every new reset key under %s to a translation, not the key', (target) => {
    setLocale(target);

    const unresolved = ADDED_KEYS.filter((key) => {
      const text = t(key as MessageKey);
      return text === key || text.trim() === '';
    });

    expect(unresolved).toEqual([]);
  });
});

describe('i18n settings keys removed by issue #35', () => {
  it.each(LOCALES)('%s keeps none of the removed Sound / Danger-zone / coming-soon keys', (target) => {
    expect(REMOVED_KEYS.filter((key) => Object.hasOwn(CATALOGS[target], key))).toEqual([]);
  });

  it.each(LOCALES)('%s keeps no leftover stub under a removed row prefix', (target) => {
    const leftovers = Object.keys(CATALOGS[target]).filter((key) =>
      REMOVED_PREFIXES.some((prefix) => key.startsWith(prefix)),
    );

    expect(leftovers).toEqual([]);
  });

  // Regression guard: the Session section's "New session" button still uses it.
  it.each(LOCALES)('%s keeps the settings.toast.newSession toast', (target) => {
    expect(hasText(CATALOGS[target], 'settings.toast.newSession')).toBe(true);
  });
});
