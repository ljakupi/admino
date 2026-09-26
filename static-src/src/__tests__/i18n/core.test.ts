/**
 * i18n core tests (issue #144: PWA internationalization, DE / FR / EN).
 *
 * `@/i18n/core` is the small in-house i18n module: `createI18n` builds an
 * instance with a reactive `locale`, `t(key, params)` with `{name}`
 * interpolation and `Intl.PluralRules` plurals, fallback active locale → en →
 * key (with a dev-only, once-per-(locale, key) console warning that never
 * leaks param values), `setLocale` that switches without a reload, and Swiss
 * (`*-CH`) date/number/CHF formatters. `splitMessage` cuts a message into text
 * and slot segments so markup can be rendered through slots, never `v-html`.
 *
 * Security: `t` inserts param values literally, in a single pass. It never
 * re-expands a placeholder found inside a value, never treats `$&`-style
 * replacement patterns specially, never reads inherited properties, and never
 * escapes or parses HTML (escaping is Vue's text rendering).
 *
 * The tests use small inline catalogs and never depend on the real catalog
 * wording. They assert on returned values, reactive state and
 * `document.documentElement.lang` only.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { computed } from 'vue';
import {
  createI18n,
  intlLocale,
  splitMessage,
  SUPPORTED_LOCALES,
  type Locale,
  type Message,
  type MessageSegment,
  type Params,
} from '@/i18n/core';

// --- Fixtures -------------------------------------------------------------

const EN = {
  greeting: 'Hello',
  welcome: 'Welcome, {name}!',
  'tools.count': { one: '{count} tool', other: '{count} tools' },
  'files.in': { one: '{count} file in {folder}', other: '{count} files in {folder}' },
  'only.en': 'English only',
  'only.en.welcome': 'Hi {name}, English only',
  'only.en.count': { one: '{count} tool', other: '{count} tools' },
} satisfies Record<string, Message>;

type Key = keyof typeof EN;

const DE: Partial<Record<Key, Message>> = {
  greeting: 'Hallo',
  welcome: 'Willkommen, {name}!',
  'tools.count': { one: '{count} Werkzeug', other: '{count} Werkzeuge' },
  'files.in': { one: '{count} Datei in {folder}', other: '{count} Dateien in {folder}' },
};

const FR: Partial<Record<Key, Message>> = {
  greeting: 'Bonjour',
  welcome: 'Bienvenue, {name} !',
  'tools.count': { one: '{count} outil', other: '{count} outils' },
  'files.in': { one: '{count} fichier dans {folder}', other: '{count} fichiers dans {folder}' },
};

const LOCALES: readonly Locale[] = ['en', 'de', 'fr'];

/** Noon UTC, so the calendar date is the same in every realistic time zone. */
const NOON_UTC = new Date(Date.UTC(2026, 2, 5, 12));

/** A param value that must never appear in a console warning. */
const USER_CONTENT = 'SECRET-USER-CONTENT-4242';

function makeI18n(options: { locale?: Locale; dev?: boolean } = {}) {
  return createI18n({ messages: { en: EN, de: DE, fr: FR }, ...options });
}

/** Render one ad-hoc en message through `t`. */
function render(message: Message, params?: Params): string {
  return createI18n({ messages: { en: { m: message } } }).t('m', params);
}

/**
 * ICU output varies by version in two harmless ways: (narrow) no-break spaces
 * vs plain spaces, and the Swiss grouping separator, which is U+2019 (’) in
 * some ICU/CLDR versions and U+0027 (') in others (e.g. Node 20.18 vs 20.20).
 * Normalize both so the assertions check the format, not the ICU build.
 */
function plain(text: string): string {
  return text.replace(/[\u00a0\u202f]/g, ' ').replace(/'/g, '\u2019');
}

/** Everything passed to console.warn, as one searchable string. */
function warnedText(calls: ReadonlyArray<readonly unknown[]>): string {
  return calls
    .map((args) =>
      args
        .map((arg) => {
          if (typeof arg === 'string') return arg;
          if (arg instanceof Error) return arg.message;
          return JSON.stringify(arg) ?? String(arg);
        })
        .join(' '),
    )
    .join('\n');
}

function silenceWarn() {
  return vi.spyOn(console, 'warn').mockImplementation(() => {});
}

afterEach(() => {
  document.documentElement.removeAttribute('lang');
});

// --- Locales --------------------------------------------------------------

describe('i18n core locales', () => {
  it('supports exactly en, de and fr', () => {
    expect([...SUPPORTED_LOCALES]).toEqual(['en', 'de', 'fr']);
  });

  it.each<[Locale, string]>([
    ['en', 'en-CH'],
    ['de', 'de-CH'],
    ['fr', 'fr-CH'],
  ])('maps %s to the Swiss Intl locale %s', (locale, tag) => {
    expect(intlLocale(locale)).toBe(tag);
  });
});

// --- Interpolation --------------------------------------------------------

describe('i18n core t interpolation', () => {
  it('returns a message without placeholders unchanged', () => {
    expect(makeI18n().t('greeting')).toBe('Hello');
  });

  it('replaces a {name} placeholder with the param', () => {
    expect(makeI18n().t('welcome', { name: 'Ada' })).toBe('Welcome, Ada!');
  });

  it('replaces every occurrence of every placeholder', () => {
    expect(render('{a} and {a} and {b}', { a: 'x', b: 'y' })).toBe('x and x and y');
  });

  it('accepts placeholder names with underscores and digits', () => {
    expect(render('{_x1}/{user_name}/{A9}', { _x1: 'p', user_name: 'q', A9: 'r' })).toBe('p/q/r');
  });

  it.each<[number, string]>([
    [0, '0 items'],
    [3, '3 items'],
    [-1.5, '-1.5 items'],
  ])('inserts the number %s as String(value)', (count, expected) => {
    expect(render('{count} items', { count })).toBe(expected);
  });

  it('does not re-expand a placeholder that appears inside a param value', () => {
    expect(render('[{a}]', { a: '{b}', b: 'B' })).toBe('[{b}]');
  });

  it('inserts $-replacement patterns literally', () => {
    const value = "$& $1 $$ $` $' $<name>";

    expect(render('[{v}]', { v: value })).toBe(`[${value}]`);
  });

  it('leaves a placeholder without a matching param untouched', () => {
    expect(render('Hi {name}, you have {count} new', { count: 2 })).toBe('Hi {name}, you have 2 new');
  });

  it('leaves placeholders untouched when no params are given', () => {
    expect(makeI18n().t('welcome')).toBe('Welcome, {name}!');
  });

  it('ignores extra params', () => {
    expect(render('Hi', { name: 'Ada', count: 1 })).toBe('Hi');
  });

  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf'])(
    'never reads the inherited property {%s} from the params',
    (name) => {
      expect(render(`[{${name}}]`, {})).toBe(`[{${name}}]`);
    },
  );

  it.each(['{ name }', '{}', '{1x}', '{na-me}', '{name', 'name}'])(
    'leaves the non-placeholder braces %j as they are',
    (message) => {
      expect(render(message, { name: 'N', '1x': 'X', '': 'E', 'na-me': 'M' })).toBe(message);
    },
  );

  it('returns an HTML param verbatim, without escaping or parsing it', () => {
    const payload = '<img src=x onerror=alert(1)>';

    expect(render('Hi {name}', { name: payload })).toBe(`Hi ${payload}`);
  });

  it('returns markup and entities in the message itself verbatim', () => {
    expect(render('<b>{x}</b> &amp; {y}', { x: '1', y: '&' })).toBe('<b>1</b> &amp; &');
  });
});

// --- Plurals --------------------------------------------------------------

describe('i18n core t plurals', () => {
  it.each<[Locale, number, string]>([
    ['en', 0, '0 tools'],
    ['en', 1, '1 tool'],
    ['en', 2, '2 tools'],
    ['fr', 0, '0 outil'],
    ['fr', 1, '1 outil'],
    ['fr', 2, '2 outils'],
    ['de', 0, '0 Werkzeuge'],
    ['de', 1, '1 Werkzeug'],
    ['de', 2, '2 Werkzeuge'],
  ])('in %s, count %d reads %j', (locale, count, expected) => {
    expect(makeI18n({ locale }).t('tools.count', { count })).toBe(expected);
  });

  it('interpolates the other params into the chosen form', () => {
    expect(makeI18n({ locale: 'de' }).t('files.in', { count: 1, folder: 'Inbox' })).toBe(
      '1 Datei in Inbox',
    );
  });

  it('uses the plural rules of the en catalog when an fr lookup falls back to en', () => {
    expect(makeI18n({ locale: 'fr' }).t('only.en.count', { count: 0 })).toBe('0 tools');
  });

  it('uses en rules for a de fallback too', () => {
    expect(makeI18n({ locale: 'de' }).t('only.en.count', { count: 1 })).toBe('1 tool');
  });

  it('selects the category with Intl.PluralRules, not by the literal count', () => {
    // English has no "zero" category: 0 selects "other".
    expect(render({ zero: 'No tools', one: '{count} tool', other: '{count} tools' }, { count: 0 })).toBe(
      '0 tools',
    );
  });

  it('uses the other form when the selected category has no form', () => {
    expect(render({ other: '{count} items' }, { count: 1 })).toBe('1 items');
  });

  it('uses the other form when count is missing', () => {
    expect(makeI18n().t('tools.count')).toBe('{count} tools');
  });

  it.each<[string, string | number, string]>([
    ['NaN', Number.NaN, 'NaN tools'],
    ['Infinity', Number.POSITIVE_INFINITY, 'Infinity tools'],
    ['a numeric string', '1', '1 tools'],
    ['a word', 'many', 'many tools'],
  ])('uses the other form when count is %s', (_label, count, expected) => {
    expect(makeI18n().t('tools.count', { count })).toBe(expected);
  });
});

// --- Fallback -------------------------------------------------------------

describe('i18n core t fallback', () => {
  it.each<[Locale, string]>([
    ['en', 'Hello'],
    ['de', 'Hallo'],
    ['fr', 'Bonjour'],
  ])('reads %s from its own catalog', (locale, expected) => {
    expect(makeI18n({ locale }).t('greeting')).toBe(expected);
  });

  it.each<Locale>(['de', 'fr'])('falls back to en for a key missing in %s', (locale) => {
    expect(makeI18n({ locale }).t('only.en.welcome', { name: 'Ada' })).toBe('Hi Ada, English only');
  });

  it('falls back to en when the locale has no catalog at all', () => {
    const i18n = createI18n({ messages: { en: { greeting: 'Hello' } }, locale: 'de' });

    expect(i18n.t('greeting')).toBe('Hello');
  });

  it.each<Locale>(['en', 'de', 'fr'])('returns the key itself when it is missing everywhere (%s)', (locale) => {
    expect(makeI18n({ locale }).t('does.not.exist' as never)).toBe('does.not.exist');
  });

  it.each<[Locale, string]>(
    LOCALES.flatMap((locale) =>
      ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf'].map(
        (key) => [locale, key] as [Locale, string],
      ),
    ),
  )('in %s returns the key %j instead of a prototype member', (locale, key) => {
    // Deliberately not a catalog key: lookups must use own properties only.
    expect(makeI18n({ locale }).t(key as never)).toBe(key);
  });
});

// --- Dev warnings ---------------------------------------------------------

describe('i18n core dev warnings', () => {
  it('warns exactly once for a key missing in the active locale, however often it is used', () => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale: 'de', dev: true });

    i18n.t('only.en');
    i18n.t('only.en');
    i18n.t('only.en');

    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('warns once per (locale, key) pair', () => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale: 'de', dev: true });

    i18n.t('only.en');
    i18n.t('only.en.welcome');
    i18n.setLocale('fr');
    i18n.t('only.en');
    i18n.t('only.en');
    i18n.setLocale('de');
    i18n.t('only.en');

    expect(warn).toHaveBeenCalledTimes(3);
  });

  it('names the key and the locale in the warning', () => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale: 'de', dev: true });

    i18n.t('only.en');

    const text = warnedText(warn.mock.calls);
    expect(text).toContain('only.en');
    expect(text).toMatch(/\bde\b/);
  });

  it.each<Locale>(['en', 'de'])('warns exactly once for a key missing everywhere (%s)', (locale) => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale, dev: true });

    i18n.t('does.not.exist' as never);
    i18n.t('does.not.exist' as never);

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warnedText(warn.mock.calls)).toContain('does.not.exist');
  });

  it('never puts param values into the warning', () => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale: 'fr', dev: true });

    i18n.t('only.en.welcome', { name: USER_CONTENT });
    i18n.t('does.not.exist' as never, { name: USER_CONTENT, count: 4242 });

    expect(warn).toHaveBeenCalled();
    expect(warnedText(warn.mock.calls)).not.toContain(USER_CONTENT);
  });

  it('does not warn for keys the active locale has', () => {
    const warn = silenceWarn();

    makeI18n({ locale: 'en', dev: true }).t('only.en');
    makeI18n({ locale: 'de', dev: true }).t('greeting');
    makeI18n({ locale: 'fr', dev: true }).t('tools.count', { count: 2 });

    expect(warn).not.toHaveBeenCalled();
  });

  it.each<[string, { dev?: boolean }]>([
    ['dev: false', { dev: false }],
    ['dev omitted', {}],
  ])('never warns with %s, but still falls back', (_label, options) => {
    const warn = silenceWarn();
    const i18n = makeI18n({ locale: 'de', ...options });

    const results = [i18n.t('only.en'), i18n.t('does.not.exist' as never)];

    expect(results).toEqual(['English only', 'does.not.exist']);
    expect(warn).not.toHaveBeenCalled();
  });
});

// --- Locale switching -----------------------------------------------------

describe('i18n core setLocale', () => {
  it('starts in en by default', () => {
    expect(makeI18n().locale.value).toBe('en');
  });

  it('starts in the initial locale option', () => {
    const i18n = makeI18n({ locale: 'fr' });

    expect([i18n.locale.value, i18n.t('greeting')]).toEqual(['fr', 'Bonjour']);
  });

  it.each<[string, Locale]>([
    ['de', 'de'],
    ['fr', 'fr'],
    ['en', 'en'],
    ['DE', 'de'],
    [' fr ', 'fr'],
    ['En', 'en'],
    ['\tde\n', 'de'],
  ])('applies %j as %s and returns it', (value, applied) => {
    const i18n = makeI18n();

    const returned = i18n.setLocale(value);

    expect([returned, i18n.locale.value]).toEqual([applied, applied]);
  });

  it.each(['it', 'xx', '', '   ', 'english'])('applies en for the unsupported value %j', (value) => {
    const i18n = makeI18n({ locale: 'de' });

    const returned = i18n.setLocale(value);

    expect([returned, i18n.locale.value, i18n.t('greeting')]).toEqual(['en', 'en', 'Hello']);
  });

  it('switches t to the new language', () => {
    const i18n = makeI18n();

    i18n.setLocale('de');

    expect(i18n.t('welcome', { name: 'Ada' })).toBe('Willkommen, Ada!');
  });

  it('updates a computed created before the switch, without a reload', () => {
    const i18n = makeI18n();
    const greeting = computed(() => i18n.t('greeting'));
    const seen = [greeting.value];

    i18n.setLocale('de');
    seen.push(greeting.value);
    i18n.setLocale('fr');
    seen.push(greeting.value);

    expect(seen).toEqual(['Hello', 'Hallo', 'Bonjour']);
  });

  it('exposes locale as a reactive ref', () => {
    const i18n = makeI18n();
    const current = computed(() => i18n.locale.value);
    const before = current.value;

    i18n.setLocale('fr');

    expect([before, current.value]).toEqual(['en', 'fr']);
  });

  it('updates a computed formatter output after the switch', () => {
    const i18n = makeI18n();
    const amount = computed(() => plain(i18n.formatChf(1234.5)));
    const before = amount.value;

    i18n.setLocale('fr');

    expect([before, amount.value]).toEqual(['CHF 1’234.50', '1 234.50 CHF']);
  });

  it.each<[string, string]>([
    ['de', 'de'],
    ['FR', 'fr'],
    ['en', 'en'],
    ['xx', 'en'],
  ])('sets <html lang> for %j to %s', (value, lang) => {
    const i18n = makeI18n({ locale: 'de' });

    i18n.setLocale(value);

    expect(document.documentElement.lang).toBe(lang);
  });
});

// --- Formatters -----------------------------------------------------------

describe('i18n core formatChf', () => {
  it.each<[Locale, string]>([
    ['de', 'CHF 1’234.50'],
    ['en', 'CHF 1’234.50'],
    ['fr', '1 234.50 CHF'],
  ])('formats 1234.5 in %s as %j', (locale, expected) => {
    expect(plain(makeI18n({ locale }).formatChf(1234.5))).toBe(expected);
  });

  it('always shows two decimals', () => {
    expect(plain(makeI18n({ locale: 'de' }).formatChf(12))).toBe('CHF 12.00');
  });
});

describe('i18n core formatNumber', () => {
  it.each<[Locale, string]>([
    ['de', '1’234’567.891'],
    ['en', '1’234’567.891'],
    ['fr', '1 234 567,891'],
  ])('formats 1234567.891 in %s as %j', (locale, expected) => {
    expect(plain(makeI18n({ locale }).formatNumber(1234567.891))).toBe(expected);
  });

  it.each<[Locale, string]>([
    ['de', '1’234.50'],
    ['fr', '1 234,50'],
  ])('passes the Intl options through in %s', (locale, expected) => {
    expect(plain(makeI18n({ locale }).formatNumber(1234.5, { minimumFractionDigits: 2 }))).toBe(
      expected,
    );
  });
});

describe('i18n core formatDate', () => {
  const MEDIUM_UTC: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeZone: 'UTC' };

  it.each<[Locale, string]>([
    ['de', '05.03.2026'],
    ['en', '5 Mar 2026'],
    ['fr', '5 mars 2026'],
  ])('formats a medium date in %s as %j', (locale, expected) => {
    expect(plain(makeI18n({ locale }).formatDate(NOON_UTC, MEDIUM_UTC))).toBe(expected);
  });

  it.each<Locale>(['en', 'de', 'fr'])('defaults to dateStyle medium in %s', (locale) => {
    const i18n = makeI18n({ locale });

    expect(i18n.formatDate(NOON_UTC)).toBe(i18n.formatDate(NOON_UTC, { dateStyle: 'medium' }));
  });

  it('uses the 24-hour clock for en', () => {
    const time = makeI18n().formatDate(NOON_UTC, { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });

    expect(plain(time)).toBe('12:00');
  });

  it('accepts a number timestamp', () => {
    expect(plain(makeI18n({ locale: 'fr' }).formatDate(NOON_UTC.getTime(), MEDIUM_UTC))).toBe(
      '5 mars 2026',
    );
  });
});

// --- splitMessage ---------------------------------------------------------

const text = (value: string): MessageSegment => ({ kind: 'text', text: value });
const slot = (name: string): MessageSegment => ({ kind: 'slot', name });

/** Rebuild the message a segment list came from. */
function join(segments: readonly MessageSegment[]): string {
  return segments.map((s) => (s.kind === 'text' ? s.text : `{${s.name}}`)).join('');
}

describe('i18n core splitMessage', () => {
  it.each<[string, MessageSegment[]]>([
    ['Plain text', [text('Plain text')]],
    ['Run {cmd} now', [text('Run '), slot('cmd'), text(' now')]],
    ['{a}{b}', [slot('a'), slot('b')]],
    ['{a} and {b}.', [slot('a'), text(' and '), slot('b'), text('.')]],
    ['', []],
    ['a { b } c {}', [text('a { b } c {}')]],
    ['{1x} {ok}', [text('{1x} '), slot('ok')]],
    ['<b>{x}</b>', [text('<b>'), slot('x'), text('</b>')]],
  ])('splits %j', (message, expected) => {
    expect(splitMessage(message)).toEqual(expected);
  });

  const SAMPLES = [
    'Plain text',
    'Run {cmd} now',
    '{a}{b}',
    '{a} and {b}.',
    '',
    'a { b } c {}',
    '{x}',
    '{x}{ y }{z}',
    '<code>{path}</code>',
  ];

  it('never produces an empty text segment', () => {
    const empty = SAMPLES.flatMap((m) => splitMessage(m)).filter(
      (s) => s.kind === 'text' && s.text === '',
    );

    expect(empty).toEqual([]);
  });

  it('keeps every character, so the segments rebuild the message', () => {
    expect(SAMPLES.map((m) => join(splitMessage(m)))).toEqual(SAMPLES);
  });
});

// --- segments (I18nT) -----------------------------------------------------
//
// `segments` feeds the `<I18nT>` component, which renders inline markup
// through named slots. It resolves a message exactly like `t` (locale
// fallback, plurals, dev warnings) but splits the message BEFORE
// interpolating: a `{slot}` with a matching own-property param becomes a text
// segment holding the param value, and a param value is never re-parsed, so
// content such as `'{cmd}'` can never turn into a slot.

const SEG_EN = {
  'cmd.first': 'Run {cmd} first',
  'hello.run': 'Hello {name}, run {cmd}',
  'runs.count': { one: 'Run {cmd} once', other: 'Run {cmd} {count} times' },
  'only.en.cmd': 'Use {cmd}',
  'only.en.count': { one: '{cmd} once', other: '{cmd} {count} times' },
} satisfies Record<string, Message>;

type SegKey = keyof typeof SEG_EN;

const SEG_DE: Partial<Record<SegKey, Message>> = {
  'cmd.first': 'Zuerst {cmd} ausführen',
  'hello.run': 'Hallo {name}, führen Sie {cmd} aus',
  'runs.count': { one: '{cmd} einmal ausführen', other: '{cmd} {count}-mal ausführen' },
};

const SEG_FR: Partial<Record<SegKey, Message>> = {
  'cmd.first': "Lancez d'abord {cmd}",
  'hello.run': 'Bonjour {name}, lancez {cmd}',
  'runs.count': { one: 'Lancer {cmd} une fois', other: 'Lancer {cmd} {count} fois' },
};

function makeSegI18n(options: { locale?: Locale; dev?: boolean } = {}) {
  return createI18n({ messages: { en: SEG_EN, de: SEG_DE, fr: SEG_FR }, ...options });
}

describe('i18n core segments', () => {
  it('keeps every placeholder as a slot when no params are given', () => {
    expect(makeSegI18n().segments('cmd.first')).toEqual([text('Run '), slot('cmd'), text(' first')]);
  });

  it('turns a placeholder with a matching param into a text segment', () => {
    expect(makeSegI18n().segments('hello.run', { name: 'Ada' })).toEqual([
      text('Hello '),
      text('Ada'),
      text(', run '),
      slot('cmd'),
    ]);
  });

  it('never re-parses a param value, so a value like {cmd} stays text', () => {
    expect(makeSegI18n().segments('hello.run', { name: '{cmd}' })).toEqual([
      text('Hello '),
      text('{cmd}'),
      text(', run '),
      slot('cmd'),
    ]);
  });

  it('inserts $& patterns and HTML in a value literally', () => {
    expect(makeSegI18n().segments('hello.run', { name: '$&$1$$<b>x</b>' })).toEqual([
      text('Hello '),
      text('$&$1$$<b>x</b>'),
      text(', run '),
      slot('cmd'),
    ]);
  });

  it('stringifies a number param', () => {
    expect(makeSegI18n().segments('hello.run', { name: 42 })).toEqual([
      text('Hello '),
      text('42'),
      text(', run '),
      slot('cmd'),
    ]);
  });

  it('produces no empty text segment for an empty param value', () => {
    expect(makeSegI18n().segments('hello.run', { name: '' })).toEqual([
      text('Hello '),
      text(', run '),
      slot('cmd'),
    ]);
  });

  it('reads own-property params only, so {constructor} stays a slot', () => {
    const i18n = createI18n({ messages: { en: { m: 'Use {constructor}' } } });

    expect(i18n.segments('m', {})).toEqual([text('Use '), slot('constructor')]);
  });

  it('picks the plural form from params.count and fills {count} as text', () => {
    const i18n = makeSegI18n();

    expect([
      i18n.segments('runs.count', { count: 3 }),
      i18n.segments('runs.count', { count: 1 }),
    ]).toEqual([
      [text('Run '), slot('cmd'), text(' '), text('3'), text(' times')],
      [text('Run '), slot('cmd'), text(' once')],
    ]);
  });

  it('uses the plural rules of the active locale', () => {
    const i18n = makeSegI18n({ locale: 'fr' });

    // French treats 0 as singular.
    expect(i18n.segments('runs.count', { count: 0 })).toEqual([
      text('Lancer '),
      slot('cmd'),
      text(' une fois'),
    ]);
  });

  it('uses English plural rules for a message that falls back to en', () => {
    const i18n = makeSegI18n({ locale: 'fr' });

    expect(i18n.segments('only.en.count', { count: 0 })).toEqual([
      slot('cmd'),
      text(' '),
      text('0'),
      text(' times'),
    ]);
  });

  it('falls back to en for a key the active locale lacks', () => {
    expect(makeSegI18n({ locale: 'de' }).segments('only.en.cmd')).toEqual([text('Use '), slot('cmd')]);
  });

  it.each(['does.not.exist', 'toString', 'constructor', '__proto__'])(
    'returns the key %j as one text segment when no catalog has it',
    (key) => {
      expect(makeSegI18n({ locale: 'de' }).segments(key as never)).toEqual([text(key)]);
    },
  );

  it('follows setLocale reactively, without a reload', () => {
    const i18n = makeSegI18n();
    const segs = computed(() => i18n.segments('cmd.first'));
    const before = segs.value;

    i18n.setLocale('de');

    expect([before, segs.value]).toEqual([
      [text('Run '), slot('cmd'), text(' first')],
      [text('Zuerst '), slot('cmd'), text(' ausführen')],
    ]);
  });

  it('shares the once-per-(locale, key) dev warning with t and never logs param values', () => {
    const warn = silenceWarn();
    const i18n = makeSegI18n({ locale: 'de', dev: true });

    i18n.t('only.en.cmd', { cmd: USER_CONTENT });
    i18n.segments('only.en.cmd', { cmd: USER_CONTENT });
    i18n.segments('only.en.cmd');

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warnedText(warn.mock.calls)).not.toContain(USER_CONTENT);
  });

  it('does not warn without dev', () => {
    const warn = silenceWarn();

    makeSegI18n({ locale: 'de' }).segments('only.en.cmd');
    makeSegI18n({ locale: 'de' }).segments('does.not.exist' as never);

    expect(warn).not.toHaveBeenCalled();
  });

  it.each<[SegKey, Params | undefined]>([
    ['cmd.first', undefined],
    ['hello.run', { name: 'Ada' }],
    ['hello.run', { name: 'Ada', cmd: 'make check' }],
    ['runs.count', { count: 3 }],
    ['runs.count', { count: 1, cmd: 'ls' }],
  ])('rebuilds exactly what t returns for %s with %j', (key, params) => {
    for (const target of LOCALES) {
      const i18n = makeSegI18n({ locale: target });

      expect(join(i18n.segments(key, params))).toBe(i18n.t(key, params));
    }
  });
});

describe('i18n core setLocale runtime robustness', () => {
  // `setLocale` receives the server's `ui_language` in #166; a malformed
  // payload must fall back to en, never throw.
  it.each<[string, unknown]>([
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['an object', {}],
    ['an array', ['de']],
  ])('applies en for %s instead of throwing', (_label, value) => {
    const i18n = makeI18n({ locale: 'de' });

    const applied = i18n.setLocale(value as never);

    expect([applied, i18n.locale.value, document.documentElement.lang]).toEqual(['en', 'en', 'en']);
  });
});
