/**
 * Browser locale service (issue #155: before login the UI language comes from
 * the browser's Accept-Language, i.e. `navigator.languages`; after login it
 * follows the profile's `ui_language`, applied by the auth store).
 *
 * `browserLocale(languages?)` returns the first entry of `languages` whose
 * primary subtag (case-insensitive, the part before `-` or `_`) is one of the
 * shipped locales, else `'en'`. With no argument it reads
 * `navigator.languages`, falling back to `[navigator.language]` when that
 * list is empty or missing.
 */
import { SUPPORTED_LOCALES, type Locale } from '@/i18n/core';

const SUPPORTED_SET: ReadonlySet<string> = new Set(SUPPORTED_LOCALES);

/** The primary language subtag of a BCP-47-ish tag (`de-CH` / `de_CH` -> `de`), lower-cased. */
function primarySubtag(tag: string): string {
  const [primary] = tag.split(/[-_]/, 1);
  return (primary ?? '').toLowerCase();
}

export function browserLocale(languages?: readonly string[]): Locale {
  const navLanguages = typeof navigator === 'undefined' ? undefined : navigator.languages;
  const navLanguage = typeof navigator === 'undefined' ? '' : navigator.language;
  const list =
    languages !== undefined
      ? languages
      : Array.isArray(navLanguages) && navLanguages.length > 0
        ? navLanguages
        : [navLanguage];

  for (const lang of list) {
    const primary = primarySubtag(lang);
    if (SUPPORTED_SET.has(primary)) return primary as Locale;
  }
  return 'en';
}
