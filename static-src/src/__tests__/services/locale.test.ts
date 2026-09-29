/**
 * Browser locale service tests (issue #155: before login the UI language
 * comes from the browser's Accept-Language, i.e. `navigator.languages`).
 *
 * `browserLocale(languages?)` returns the first entry whose primary subtag
 * (case-insensitive, the part before `-` or `_`) is one of the shipped
 * locales (en, de, fr), else `'en'`. With no argument it reads
 * `navigator.languages`, falling back to `[navigator.language]` when that
 * list is empty or missing. `navigator` is stubbed per test through getter
 * spies (restored automatically).
 */
import { describe, it, expect, vi } from 'vitest';
import { browserLocale } from '@/services/locale';

function stubNavigator(languages: readonly string[] | undefined, language: string): void {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(languages as readonly string[]);
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(language);
}

describe('browserLocale with an explicit list', () => {
  it.each([
    [['de-CH', 'en'], 'de'],
    [['it-CH', 'fr-CH'], 'fr'],
    [['EN-us'], 'en'],
    [['fr_CH'], 'fr'],
    [['DE'], 'de'],
    [['de-CH-1996'], 'de'],
    [['en-GB', 'de'], 'en'],
    [['it', 'es'], 'en'],
    [[], 'en'],
    [['', 'd', 'deu', 'fr'], 'fr'],
    [['deu'], 'en'],
    [['d'], 'en'],
    [['fra-CH', 'de'], 'de'],
    [['en_US'], 'en'],
  ] as Array<[string[], string]>)('%j gives %s', (languages, expected) => {
    expect(browserLocale(languages)).toBe(expected);
  });

  it('prefers the argument over navigator.languages', () => {
    stubNavigator(['de-CH'], 'de-CH');

    expect(browserLocale(['fr-CH'])).toBe('fr');
  });
});

describe('browserLocale from navigator', () => {
  it('reads navigator.languages when called without an argument', () => {
    stubNavigator(['fr-CH', 'de'], 'fr-CH');

    expect(browserLocale()).toBe('fr');
  });

  it('skips unsupported languages in navigator.languages', () => {
    stubNavigator(['it-CH', 'rm', 'de-CH'], 'it-CH');

    expect(browserLocale()).toBe('de');
  });

  it('falls back to navigator.language when navigator.languages is empty', () => {
    stubNavigator([], 'de-CH');

    expect(browserLocale()).toBe('de');
  });

  it('falls back to navigator.language when navigator.languages is missing', () => {
    stubNavigator(undefined, 'fr');

    expect(browserLocale()).toBe('fr');
  });

  it("uses navigator.language only as a fallback, never next to a non-empty list", () => {
    stubNavigator(['it'], 'de');

    expect(browserLocale()).toBe('en');
  });

  it("returns 'en' when nothing supported is found", () => {
    stubNavigator([], '');

    expect(browserLocale()).toBe('en');
  });
});
