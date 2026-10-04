/**
 * Chat error service tests (issue #242: V1 model policy; decision D3 — every
 * chat reply with status "error" shows translated text in the UI).
 *
 * `@/services/chatErrors` is a pure module that maps the backend's
 * `ChatResponse.error_code` to an i18n catalog key. Contract (GH-242 §6):
 * - `LLM_ERROR_CODES`: exactly the seven `LLMErrorCode` values
 *   (not_configured, missing_model, provider_unavailable, rate_limited,
 *   timeout, residency_blocked, context_too_long).
 * - `chatErrorKey(code: unknown)`: `chat.error.<code>` for a known code;
 *   `chat.error.generic` for anything else — null, undefined, '', an unknown
 *   string, a near miss ('TIMEOUT', ' timeout'), a non-string (number,
 *   object, array, boxed String) and prototype names such as '__proto__',
 *   'toString' or 'constructor'.
 *
 * Every key `chatErrorKey` can return must exist in the en, de and fr
 * catalogs, so the store's `t(chatErrorKey(...))` never falls back to the raw
 * key (cross-check with the catalogs; `i18n/modelPolicyKeys.test.ts` pins the
 * same keys independently).
 *
 * Security notes: the mapping fails closed to the generic text, and a crafted
 * `error_code` can never resolve to an inherited property or to a key outside
 * `chat.error.*`. No component is mounted and nothing touches the network.
 */
import { describe, it, expect } from 'vitest';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import { LLM_ERROR_CODES, chatErrorKey } from '@/services/chatErrors';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const LOCALES: readonly CatalogLocale[] = ['en', 'de', 'fr'];

/** The seven codes the backend's `LLMErrorCode` Literal defines (GH-242 §1). */
const CODES: readonly string[] = [
  'not_configured',
  'missing_model',
  'provider_unavailable',
  'rate_limited',
  'timeout',
  'residency_blocked',
  'context_too_long',
];

const GENERIC_KEY = 'chat.error.generic';

/** Inputs that are not a known code: each must map to the generic key. */
const NOT_A_CODE: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['undefined', undefined],
  ['the empty string', ''],
  ['an unknown string', 'quota_exceeded'],
  ['the word generic', 'generic'],
  ['an upper-case near miss', 'TIMEOUT'],
  ['a padded near miss', ' timeout'],
  ['a dotted path', 'error.timeout'],
  ['a number', 429],
  ['NaN', Number.NaN],
  ['a boolean', true],
  ['a plain object', {}],
  ['an object carrying a code', { code: 'timeout' }],
  ['an array holding a code', ['timeout']],
  ['a boxed String', new String('timeout')],
  ['__proto__', '__proto__'],
  ['toString', 'toString'],
  ['constructor', 'constructor'],
  ['hasOwnProperty', 'hasOwnProperty'],
  ['valueOf', 'valueOf'],
];

function hasText(catalog: Record<string, unknown>, key: string): boolean {
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  return typeof value === 'string' && value.trim() !== '';
}

describe('LLM_ERROR_CODES', () => {
  it('lists exactly the seven backend error codes, each once', () => {
    const listed = [...LLM_ERROR_CODES];

    expect({ sorted: [...listed].sort(), length: listed.length }).toEqual({
      sorted: [...CODES].sort(),
      length: CODES.length,
    });
  });
});

describe('chatErrorKey', () => {
  it.each(CODES)('maps the known code %s to chat.error.<code>', (code) => {
    expect(chatErrorKey(code)).toBe(`chat.error.${code}`);
  });

  it.each(NOT_A_CODE)('maps %s to chat.error.generic', (_label, input) => {
    expect(chatErrorKey(input)).toBe(GENERIC_KEY);
  });

  it('gives each known code its own key, distinct from the generic one', () => {
    const keys = CODES.map((code) => chatErrorKey(code));

    expect({ distinct: new Set(keys).size, hasGeneric: keys.includes(GENERIC_KEY) }).toEqual({
      distinct: CODES.length,
      hasGeneric: false,
    });
  });

  it('maps every listed LLM_ERROR_CODES entry to its own chat.error key', () => {
    expect(LLM_ERROR_CODES.map((code) => chatErrorKey(code))).toEqual(
      [...LLM_ERROR_CODES].map((code) => `chat.error.${code}`),
    );
  });

  it.each(LOCALES)('returns only keys the %s catalog defines with a non-blank string', (target) => {
    const returned = [...CODES, null, 'quota_exceeded', '__proto__'].map((code) => chatErrorKey(code));

    expect(returned.filter((key) => !hasText(CATALOGS[target], key))).toEqual([]);
  });
});
