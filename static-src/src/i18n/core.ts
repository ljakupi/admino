/**
 * i18n core (issue #144: PWA internationalization, DE / FR / EN).
 *
 * Framework-light factory for a small in-house i18n instance: a reactive
 * `locale`, `t(key, params)` with `{name}` interpolation and
 * `Intl.PluralRules`-driven plurals, fallback active locale -> en -> the key
 * itself (with a dev-only, once-per-(locale, key) console warning that never
 * leaks param values), `setLocale` that switches without a reload, and Swiss
 * (`*-CH`) date/number/CHF formatters. `splitMessage` cuts a message into
 * text and slot segments, and `segments` resolves a key like `t` but splits
 * the message *before* interpolating, so `<I18nT>` can render inline markup
 * through component slots instead of `v-html`.
 *
 * This module is pure and framework-light: it only reaches into Vue for
 * `ref`/`readonly` so `locale` stays reactive across the app, and into the
 * DOM to keep `<html lang>` in sync with the active locale.
 *
 * Security notes: `t` inserts param values literally, in a single
 * `String.prototype.replace` pass with a replacer *function* (never a
 * replacement string), so values can never re-expand a placeholder, are
 * never treated as `$&`-style patterns, and are never parsed as HTML —
 * escaping is left to Vue's text rendering. `segments` keeps the same
 * guarantee: a param value becomes a text segment and is never re-split, so
 * content such as `'{cmd}'` can never turn into a slot. All lookups (catalog keys and
 * param names) use `Object.hasOwn` so a crafted key/param name can never read
 * an inherited property (e.g. `constructor`, `__proto__`).
 */
import { readonly, ref, type Ref } from 'vue';

/** The three locales admino ships. */
export type Locale = 'en' | 'de' | 'fr';

/** Locales supported by the app, in display order. */
export const SUPPORTED_LOCALES: readonly Locale[] = ['en', 'de', 'fr'];

const SUPPORTED_LOCALE_SET: ReadonlySet<string> = new Set(SUPPORTED_LOCALES);

/** Valid LDML plural categories (a superset of what any single locale uses). */
export type PluralCategory = 'zero' | 'one' | 'two' | 'few' | 'many' | 'other';

/** A pluralized message: one string per LDML category that applies; `other` is required. */
export type PluralMessage = Partial<Record<PluralCategory, string>> & { other: string };

/** A single catalog entry: a plain string, or a pluralized message. */
export type Message = string | PluralMessage;

/** A flat catalog: dotted keys to messages. */
export type Catalog = Record<string, Message>;

/** Interpolation params: `{name}` placeholders are replaced with `String(value)`. */
export type Params = Record<string, string | number>;

/** One piece of a message split by `splitMessage`: literal text or a named slot. */
export type MessageSegment = { kind: 'text'; text: string } | { kind: 'slot'; name: string };

/** Catalogs for every locale; only `en` (the source catalog) is required. */
export type Messages<En extends Catalog = Catalog> = { en: En } & Partial<
  Record<Exclude<Locale, 'en'>, Partial<Record<keyof En, Message>>>
>;

export interface I18nOptions<En extends Catalog = Catalog> {
  messages: Messages<En>;
  /** Initial locale. Defaults to `'en'`. */
  locale?: Locale;
  /** Enables the once-per-(locale, key) missing-translation console warning. */
  dev?: boolean;
}

export interface I18n<En extends Catalog = Catalog> {
  /** The active locale. Reactive; switches with `setLocale`, never a reload. */
  locale: Readonly<Ref<Locale>>;
  /** Resolves `key` in the active locale (falling back to en, then the key itself) and interpolates `params`. */
  t: (key: keyof En & string, params?: Params) => string;
  /**
   * Resolves `key` like `t`, then splits the message into text and `{slot}`
   * segments before interpolating: a slot with a matching own-property param
   * becomes a text segment holding that value (never re-split); the others
   * stay slots for `<I18nT>` to fill.
   */
  segments: (key: keyof En & string, params?: Params) => MessageSegment[];
  /** Normalizes `value` to a supported locale (else `'en'`, also for a non-string), applies it and returns it. */
  setLocale: (value: string) => Locale;
  /** Formats a date/timestamp with the active locale's Swiss (`*-CH`) tag. Defaults to `dateStyle: 'medium'`. */
  formatDate: (value: Date | number, options?: Intl.DateTimeFormatOptions) => string;
  /** Formats a number with the active locale's Swiss (`*-CH`) tag. */
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
  /** Formats a CHF amount (always two decimals) with the active locale's Swiss (`*-CH`) tag. */
  formatChf: (value: number) => string;
}

/** Maps an app `Locale` to its Swiss `Intl` locale tag. */
export function intlLocale(locale: Locale): string {
  return `${locale}-CH`;
}

const PLACEHOLDER_RE = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

function hasOwn(
  record: Record<string, unknown> | undefined,
  key: string,
): record is Record<string, unknown> {
  return record !== undefined && Object.hasOwn(record, key);
}

/** Replaces every `{name}` placeholder that has a matching own-property param; leaves the rest untouched. */
function interpolate(message: string, params: Params | undefined): string {
  return message.replace(PLACEHOLDER_RE, (match: string, name: string): string => {
    if (params !== undefined && Object.hasOwn(params, name)) {
      return String(params[name]);
    }
    return match;
  });
}

const pluralRulesCache = new Map<Locale, Intl.PluralRules>();

function pluralRulesFor(locale: Locale): Intl.PluralRules {
  let rules = pluralRulesCache.get(locale);
  if (!rules) {
    rules = new Intl.PluralRules(intlLocale(locale));
    pluralRulesCache.set(locale, rules);
  }
  return rules;
}

/** Resolves the plural form for `count` (defaulting to `other` when count is missing or not a finite number). */
function resolvePluralForm(message: PluralMessage, locale: Locale, params: Params | undefined): string {
  const count = params !== undefined && Object.hasOwn(params, 'count') ? params.count : undefined;
  const category: PluralCategory =
    typeof count === 'number' && Number.isFinite(count) ? pluralRulesFor(locale).select(count) : 'other';
  return (Object.hasOwn(message, category) ? message[category] : undefined) ?? message.other;
}

/**
 * Cuts `message` into literal-text and `{slot}` segments (never an empty
 * text segment); the segments rebuild the original message exactly.
 */
export function splitMessage(message: string): MessageSegment[] {
  const segments: MessageSegment[] = [];
  let lastIndex = 0;
  for (const match of message.matchAll(PLACEHOLDER_RE)) {
    const start = match.index;
    if (start > lastIndex) {
      segments.push({ kind: 'text', text: message.slice(lastIndex, start) });
    }
    segments.push({ kind: 'slot', name: match[1] });
    lastIndex = start + match[0].length;
  }
  if (lastIndex < message.length) {
    segments.push({ kind: 'text', text: message.slice(lastIndex) });
  }
  return segments;
}

/** Builds a new i18n instance from `messages` (see {@link I18nOptions}). */
export function createI18n<En extends Catalog>(options: I18nOptions<En>): I18n<En> {
  // `de`/`fr` are `Partial<Record<keyof En, Message>>` in `I18nOptions` (a
  // locale may translate only some of `en`'s keys, e.g. in tests); widened
  // to `Catalog` here since every lookup below already checks `hasOwn`
  // before reading, so a genuinely missing key is handled, never assumed present.
  const catalogs: Partial<Record<Locale, Catalog>> = {
    en: options.messages.en,
    de: options.messages.de as Catalog | undefined,
    fr: options.messages.fr as Catalog | undefined,
  };
  const dev = options.dev ?? false;
  const warned = new Set<string>();

  const localeRef = ref<Locale>(options.locale ?? 'en');

  function applyHtmlLang(value: Locale): void {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = value;
    }
  }
  applyHtmlLang(localeRef.value);

  function warnMissing(missingLocale: Locale, key: string): void {
    if (!dev) return;
    const dedupeKey = `${missingLocale}:${key}`;
    if (warned.has(dedupeKey)) return;
    warned.add(dedupeKey);
    // eslint-disable-next-line no-console -- intentional dev-only diagnostic
    console.warn(`[i18n] Missing translation for key "${key}" in locale "${missingLocale}"`);
  }

  /**
   * Picks the message form for `key` (active locale -> en -> undefined),
   * resolving plurals with the rules of the locale that supplied the message.
   * Warns (dev only) when the active locale lacks the key.
   */
  function resolveForm(key: string, params: Params | undefined): string | undefined {
    const activeLocale = localeRef.value;
    let source: Locale | undefined;
    if (hasOwn(catalogs[activeLocale], key)) {
      source = activeLocale;
    } else {
      warnMissing(activeLocale, key);
      if (activeLocale !== 'en' && hasOwn(catalogs.en, key)) source = 'en';
    }
    if (source === undefined) return undefined;

    const value = catalogs[source]?.[key] as Message;
    return typeof value === 'string' ? value : resolvePluralForm(value, source, params);
  }

  function t(key: string, params?: Params): string {
    const form = resolveForm(key, params);
    return form === undefined ? key : interpolate(form, params);
  }

  function segments(key: string, params?: Params): MessageSegment[] {
    const form = resolveForm(key, params);
    if (form === undefined) return [{ kind: 'text', text: key }];

    return splitMessage(form).flatMap((segment): MessageSegment[] => {
      if (segment.kind === 'text' || params === undefined || !Object.hasOwn(params, segment.name)) {
        return [segment];
      }
      const value = String(params[segment.name]);
      return value === '' ? [] : [{ kind: 'text', text: value }];
    });
  }

  function setLocale(value: string): Locale {
    // `value` comes from the server in #166; tolerate a malformed payload.
    const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
    const applied = SUPPORTED_LOCALE_SET.has(normalized) ? (normalized as Locale) : 'en';
    localeRef.value = applied;
    applyHtmlLang(applied);
    return applied;
  }

  function formatDate(value: Date | number, options?: Intl.DateTimeFormatOptions): string {
    return new Intl.DateTimeFormat(intlLocale(localeRef.value), options ?? { dateStyle: 'medium' }).format(
      value,
    );
  }

  function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
    return new Intl.NumberFormat(intlLocale(localeRef.value), options).format(value);
  }

  function formatChf(value: number): string {
    return new Intl.NumberFormat(intlLocale(localeRef.value), {
      style: 'currency',
      currency: 'CHF',
      currencyDisplay: 'code',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(value);
  }

  return {
    locale: readonly(localeRef),
    t: t as I18n<En>['t'],
    segments: segments as I18n<En>['segments'],
    setLocale,
    formatDate,
    formatNumber,
    formatChf,
  };
}
