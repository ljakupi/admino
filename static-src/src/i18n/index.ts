/**
 * App-wide i18n singleton (issue #144: PWA internationalization, DE / FR / EN).
 *
 * Builds the one `createI18n` instance the whole app shares from the real
 * `en`/`de`/`fr` catalogs and re-exports its members so components and
 * stores can `import { t } from '@/i18n'` directly, or call `useI18n()`
 * (always the same instance — there is nothing per-component to set up).
 *
 * Starts in `'en'`, with no browser-language detection: every screen must
 * read exactly as it did before this issue. Issue #166 will later call
 * `setLocale(user.ui_language)` once the setting exists server-side.
 */
import { createI18n } from './core';
import { de } from './locales/de';
import { en } from './locales/en';
import { fr } from './locales/fr';

export const i18n = createI18n({
  messages: { en, de, fr },
  locale: 'en',
  dev: import.meta.env.DEV,
});

/** Every key the source (`en`) catalog defines; the type every catalog and lookup is checked against. */
export type MessageKey = keyof typeof en;

export const { locale, t, segments, setLocale, formatDate, formatNumber, formatChf } = i18n;

/** Returns the app-wide i18n instance (there is only one; no setup needed). */
export function useI18n() {
  return i18n;
}

export type { Locale, Message, MessageSegment, Params, PluralCategory, PluralMessage } from './core';
