/**
 * Platform defaults pure services tests (issue #168: Platform console UI for
 * the Super Admin, the Defaults tab: #160's platform defaults plus #242's
 * model fields: provider, model, max input tokens, image input, retry limit).
 *
 * `@/services/platformDefaults` holds the framework-free logic the Defaults
 * tab and `stores/platformDefaults.ts` share (contract GH-168, "Pure services:
 * src/services/platformDefaults.ts"):
 * - `LLM_PROVIDERS` (infomaniak, vllm, anthropic, openai) and `isLlmProvider`
 *   (exact, case-sensitive; prototype keys and non-strings are false);
 * - `MODEL_FIELD` (provider -> its model field), `modelOptions` (a copy of the
 *   provider's available models; none for anthropic and openai) and
 *   `providerKeyConfigured` (the key/token flag; null for vllm, it has none);
 * - `isValidModelName`: the backend's model-name rule
 *   (`[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}`, full match, strings only);
 * - `DEFAULTS_BOUNDS`: every numeric default's bounds, exactly the backend's
 *   (`src/admino/models.py`: `SettingsPatchLLM`, `Platform*Patch`, the audit
 *   retention and session bounds); GH-190 (Decision 15, contract C13):
 *   `limits.max_context_messages` is 0 (no cap) to 200, so the form accepts 0;
 * - `draftFrom`: a deep copy of exactly the editable fields (never the counts,
 *   the key flags or the available model lists);
 * - `validateDraft`: a range error for every numeric field that isn't an
 *   integer within its bounds, a provider error, a model-name error for a
 *   CHANGED model only (an unchanged model, even '', is never an error), an
 *   image-input error for a non-boolean and the trash order rule (minimum
 *   not above maximum, checked only when both are in range);
 * - `buildDefaultsPatch`: only the changed fields, grouped by section; null
 *   when nothing changed; never the read-only fields nor
 *   `confirm_residency_orgs` (the store adds that only after the residency
 *   confirmation).
 *
 * Expected strings are read from the real en/de/fr catalogs and interpolated
 * here, never hard-coded; the bounds are pinned here from the backend, never
 * read from the module under test. Security notes: no secret is ever part of
 * a draft or a patch (only `*_configured` flags exist) and nothing here may
 * write to the console. No component is mounted and nothing touches the
 * network.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import type { LlmProvider, PlatformSettings } from '@/api/types';
import { setLocale } from '@/i18n';
import { de } from '@/i18n/locales/de';
import { en } from '@/i18n/locales/en';
import { fr } from '@/i18n/locales/fr';
import {
  DEFAULTS_BOUNDS,
  LLM_PROVIDERS,
  MODEL_FIELD,
  buildDefaultsPatch,
  draftFrom,
  isLlmProvider,
  isValidModelName,
  modelOptions,
  providerKeyConfigured,
  validateDraft,
  type DefaultsDraft,
} from '@/services/platformDefaults';

type CatalogLocale = 'en' | 'de' | 'fr';

const CATALOGS: Record<CatalogLocale, Record<string, unknown>> = { en, de, fr };
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/**
 * The catalog's own string for `key` with its `{param}`s filled in one pass
 * (the same literal substitution `t` does, numbers as `String(n)`). Throws
 * when the catalog has no non-blank string for the key, so a missing key
 * never makes a comparison vacuous.
 */
function catalogText(
  locale: CatalogLocale,
  key: string,
  params: Record<string, string | number> = {},
): string {
  const catalog = CATALOGS[locale];
  const value = Object.hasOwn(catalog, key) ? catalog[key] : undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`test setup: the ${locale} catalog has no text for ${key}`);
  }
  return value.replace(PLACEHOLDER, (match: string, name: string): string =>
    Object.hasOwn(params, name) ? String(params[name]) : match,
  );
}

/** Wraps each value in its own tuple: it.each would spread a bare array case. */
function wrap(values: unknown[]): Array<[unknown]> {
  return values.map((value): [unknown] => [value]);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

beforeEach(() => {
  setLocale('en');
});

afterEach(() => {
  setLocale('en');
});

// --- Fixtures ---------------------------------------------------------------------------

/** A fresh, in-range platform settings response (trash 0..90 so every bound can be probed alone). */
function rawSettings(): PlatformSettings {
  return {
    llm: {
      provider: 'infomaniak',
      anthropic_model: 'claude-sonnet-4-5',
      openai_model: 'gpt-4o',
      infomaniak_model: 'mixtral',
      vllm_model: '',
      infomaniak_available_models: ['mixtral', 'llama3', 'qwen3'],
      vllm_available_models: ['Qwen/Qwen2.5-0.5B-Instruct'],
      max_input_tokens: 200000,
      image_input: true,
      max_retries: 2,
      residency_orgs: 3,
      anthropic_key_configured: false,
      openai_key_configured: true,
      infomaniak_token_configured: true,
    },
    limits: {
      max_tool_calls_per_message: 10,
      max_pending_confirmations: 5,
      confirmation_timeout_s: 300,
      max_message_length: 10000,
      max_context_messages: 50,
    },
    files: { max_file_size_mb: 50, max_files_per_message: 10, max_pages_per_file: 100, render_dpi: 150 },
    retention: { trash_min_days: 0, trash_max_days: 90, audit_months: 12, org_deletion_grace_days: 30 },
    security: {
      rate_limit_per_minute: 20,
      lockout_after_failures: 10,
      lockout_window_minutes: 15,
      lockout_minutes: 15,
      session_idle_timeout_minutes: 60,
      session_max_lifetime_hours: 24,
    },
  };
}

/** Deep-frozen: any function that writes into the stored settings throws. */
const STORED: PlatformSettings = deepFreeze(rawSettings());

/** The editable fields of `rawSettings()`, written out by hand (not via draftFrom). */
function baseDraft(): DefaultsDraft {
  return {
    llm: {
      provider: 'infomaniak',
      infomaniak_model: 'mixtral',
      vllm_model: '',
      anthropic_model: 'claude-sonnet-4-5',
      openai_model: 'gpt-4o',
      max_input_tokens: 200000,
      image_input: true,
      max_retries: 2,
    },
    limits: {
      max_tool_calls_per_message: 10,
      max_pending_confirmations: 5,
      confirmation_timeout_s: 300,
      max_message_length: 10000,
      max_context_messages: 50,
    },
    files: { max_file_size_mb: 50, max_files_per_message: 10, max_pages_per_file: 100, render_dpi: 150 },
    retention: { trash_min_days: 0, trash_max_days: 90, audit_months: 12, org_deletion_grace_days: 30 },
    security: {
      rate_limit_per_minute: 20,
      lockout_after_failures: 10,
      lockout_window_minutes: 15,
      lockout_minutes: 15,
      session_idle_timeout_minutes: 60,
      session_max_lifetime_hours: 24,
    },
  };
}

type Sections = Record<string, Record<string, unknown>>;

/** A fresh base draft with each `'<section>.<field>'` path set to the given value. */
function draftWith(values: Record<string, unknown>): DefaultsDraft {
  const draft = baseDraft();
  for (const [path, value] of Object.entries(values)) {
    const [section, field] = path.split('.');
    (draft as unknown as Sections)[section][field] = value;
  }
  return draft;
}

function storedValue(path: string): unknown {
  const [section, field] = path.split('.');
  return (STORED as unknown as Sections)[section][field];
}

/** `{ section: { field: value } }` for one `'<section>.<field>'` path. */
function patchOf(path: string, value: unknown): Record<string, Record<string, unknown>> {
  const [section, field] = path.split('.');
  return { [section]: { [field]: value } };
}

/** The backend bounds (src/admino/models.py, audit_events, sessions), pinned here. */
const BOUNDS: Array<[string, number, number]> = [
  ['llm.max_input_tokens', 1000, 2000000],
  ['llm.max_retries', 0, 5],
  ['limits.max_tool_calls_per_message', 1, 100],
  ['limits.max_pending_confirmations', 1, 50],
  ['limits.confirmation_timeout_s', 10, 3600],
  ['limits.max_message_length', 1, 100000],
  // GH-190 (Decision 15): 0 means no cap (the token budget alone decides).
  ['limits.max_context_messages', 0, 200],
  ['files.max_file_size_mb', 1, 500],
  ['files.max_files_per_message', 1, 50],
  ['files.max_pages_per_file', 1, 1000],
  ['files.render_dpi', 72, 300],
  ['retention.trash_min_days', 0, 90],
  ['retention.trash_max_days', 0, 90],
  ['retention.audit_months', 6, 84],
  ['retention.org_deletion_grace_days', 7, 90],
  ['security.rate_limit_per_minute', 1, 600],
  ['security.lockout_after_failures', 3, 100],
  ['security.lockout_window_minutes', 1, 1440],
  ['security.lockout_minutes', 1, 1440],
  ['security.session_idle_timeout_minutes', 15, 480],
  ['security.session_max_lifetime_hours', 1, 72],
];

const MODEL_PATHS = ['llm.infomaniak_model', 'llm.vllm_model', 'llm.anthropic_model', 'llm.openai_model'] as const;

function rangeError(min: number, max: number, locale: CatalogLocale = 'en'): string {
  return catalogText(locale, 'platform.defaults.error.range', { min, max });
}

// --- Providers ---------------------------------------------------------------------------

describe('LLM_PROVIDERS / isLlmProvider', () => {
  it('lists infomaniak, vllm, anthropic and openai in that order', () => {
    expect([...LLM_PROVIDERS]).toEqual(['infomaniak', 'vllm', 'anthropic', 'openai']);
  });

  it.each(['infomaniak', 'vllm', 'anthropic', 'openai'])('accepts %s', (provider) => {
    expect(isLlmProvider(provider)).toBe(true);
  });

  it.each(
    wrap([
      'Infomaniak',
      'OPENAI',
      'vLLM',
      ' vllm',
      'vllm ',
      '',
      'local',
      'claude',
      'mistral',
      '__proto__',
      'constructor',
      'toString',
      'hasOwnProperty',
      'valueOf',
      'length',
      1,
      null,
      undefined,
      {},
      ['openai'],
    ]),
  )('refuses %j', (value) => {
    expect(isLlmProvider(value)).toBe(false);
  });
});

describe('MODEL_FIELD', () => {
  it('maps every provider to its own model field', () => {
    expect({ ...MODEL_FIELD }).toStrictEqual({
      infomaniak: 'infomaniak_model',
      vllm: 'vllm_model',
      anthropic: 'anthropic_model',
      openai: 'openai_model',
    });
  });
});

describe('modelOptions', () => {
  it.each([
    ['infomaniak', ['mixtral', 'llama3', 'qwen3']],
    ['vllm', ['Qwen/Qwen2.5-0.5B-Instruct']],
    ['anthropic', []],
    ['openai', []],
  ] as Array<[LlmProvider, string[]]>)('%s -> %j', (provider, options) => {
    expect(modelOptions(STORED.llm, provider)).toEqual(options);
  });

  it.each(['infomaniak', 'vllm'] as const)('%s: returns a copy, never the settings array itself', (provider) => {
    const settings = rawSettings();
    const before = rawSettings();

    const options = modelOptions(settings.llm, provider);
    options.push('injected-model');

    expect([
      options !== settings.llm.infomaniak_available_models && options !== settings.llm.vllm_available_models,
      settings.llm.infomaniak_available_models,
      settings.llm.vllm_available_models,
    ]).toEqual([true, before.llm.infomaniak_available_models, before.llm.vllm_available_models]);
  });
});

describe('providerKeyConfigured', () => {
  const PROVIDERS: readonly LlmProvider[] = ['infomaniak', 'vllm', 'anthropic', 'openai'];

  function flags(llm: PlatformSettings['llm']): Record<string, boolean | null> {
    return Object.fromEntries(PROVIDERS.map((provider) => [provider, providerKeyConfigured(llm, provider)]));
  }

  it('reads each provider\'s own flag; vllm has no key (null)', () => {
    expect(flags(STORED.llm)).toStrictEqual({ infomaniak: true, vllm: null, anthropic: false, openai: true });
  });

  it('follows the flags when they flip', () => {
    const llm = {
      ...rawSettings().llm,
      infomaniak_token_configured: false,
      anthropic_key_configured: true,
      openai_key_configured: false,
    };

    expect(flags(llm)).toStrictEqual({ infomaniak: false, vllm: null, anthropic: true, openai: false });
  });
});

// --- Model names ------------------------------------------------------------------------

describe('isValidModelName', () => {
  it.each([
    'a',
    'A',
    '0',
    'gpt-4o',
    'claude-sonnet-4-5',
    'Qwen/Qwen2.5-7B-Instruct',
    'llama3.1:8b',
    'mistral_large',
    'x'.repeat(200),
    `a${'-'.repeat(199)}`,
  ])('accepts %j', (name) => {
    expect(isValidModelName(name)).toBe(true);
  });

  it.each(
    wrap([
      '',
      'a\n',
      '\na',
      '-x',
      '_x',
      '.x',
      ':x',
      '/x',
      'x'.repeat(201),
      'a b',
      ' a',
      'a ',
      'a;rm',
      'a$(id)',
      'a`id`',
      'a|b',
      'a&b',
      'a\u0000',
      'a​',
      'modèle',
      42,
      null,
      undefined,
      {},
      ['gpt-4o'],
    ]),
  )('refuses %j', (value) => {
    expect(isValidModelName(value)).toBe(false);
  });
});

// --- Bounds -------------------------------------------------------------------------------

describe('DEFAULTS_BOUNDS', () => {
  it('holds exactly the backend bounds for every numeric default', () => {
    expect(DEFAULTS_BOUNDS).toEqual(Object.fromEntries(BOUNDS.map(([path, min, max]) => [path, { min, max }])));
  });
});

// --- Draft ----------------------------------------------------------------------------------

describe('draftFrom', () => {
  it('copies exactly the editable fields (no counts, key flags or available model lists)', () => {
    expect(draftFrom(STORED)).toStrictEqual(baseDraft());
  });

  it('is a deep copy: editing the draft never changes the settings', () => {
    const settings = rawSettings();

    const draft = draftFrom(settings);
    draft.llm.provider = 'openai';
    draft.llm.max_retries = 5;
    draft.llm.vllm_model = 'edited';
    draft.limits.max_message_length = 1;
    draft.files.render_dpi = 300;
    draft.retention.audit_months = 84;
    draft.security.lockout_minutes = 1;

    expect(settings).toStrictEqual(rawSettings());
  });

  it('is a deep copy: editing the settings afterwards never changes the draft', () => {
    const settings = rawSettings();

    const draft = draftFrom(settings);
    settings.llm.max_retries = 0;
    settings.limits.max_context_messages = 1;
    settings.security.session_max_lifetime_hours = 1;

    expect(draft).toStrictEqual(baseDraft());
  });
});

// --- Validation ------------------------------------------------------------------------------

describe('validateDraft', () => {
  it('an unchanged draft has no error', () => {
    expect(validateDraft(baseDraft(), STORED)).toStrictEqual({});
  });

  it.each(BOUNDS)('%s: integers from %d to %d pass; anything else is the range error', (path, min, max) => {
    const message = rangeError(min, max);
    const errorsFor = (value: number): Record<string, string> => validateDraft(draftWith({ [path]: value }), STORED);

    expect({
      belowMin: errorsFor(min - 1),
      atMin: errorsFor(min),
      atMax: errorsFor(max),
      aboveMax: errorsFor(max + 1),
      fraction: errorsFor(min + 0.5),
      nan: errorsFor(Number.NaN),
      infinity: errorsFor(Number.POSITIVE_INFINITY),
    }).toStrictEqual({
      belowMin: { [path]: message },
      atMin: {},
      atMax: {},
      aboveMax: { [path]: message },
      fraction: { [path]: message },
      nan: { [path]: message },
      infinity: { [path]: message },
    });
  });

  it.each(
    // GH-190: with 0 in range, values that coerce to 0 (null, false, '', '0') stay errors.
    wrap(['20', null, undefined, true, false, '', '0']).map(([value]): [string, unknown] => [
      'limits.max_context_messages',
      value,
    ]),
  )('%s set to the non-number %j is the range error', (path, value) => {
    expect(validateDraft(draftWith({ [path]: value }), STORED)).toStrictEqual({ [path]: rangeError(0, 200) });
  });

  it('GH-190: limits.max_context_messages 0 (no cap) is valid; -1 and 201 are still the range error', () => {
    const path = 'limits.max_context_messages';
    const errorsFor = (value: number): Record<string, string> => validateDraft(draftWith({ [path]: value }), STORED);

    expect({
      bounds: DEFAULTS_BOUNDS[path],
      zero: errorsFor(0),
      minusOne: errorsFor(-1),
      above: errorsFor(201),
    }).toStrictEqual({
      bounds: { min: 0, max: 200 },
      zero: {},
      minusOne: { [path]: rangeError(0, 200) },
      above: { [path]: rangeError(0, 200) },
    });
  });

  it.each(['infomaniak', 'vllm', 'anthropic', 'openai'])('the provider %s is valid', (provider) => {
    expect(validateDraft(draftWith({ 'llm.provider': provider }), STORED)).toStrictEqual({});
  });

  it.each(
    wrap([
      'mistral',
      'OpenAI',
      'INFOMANIAK',
      ' vllm',
      'vllm ',
      '',
      '__proto__',
      'constructor',
      'toString',
      1,
      null,
      undefined,
    ]),
  )('a provider of %j is the provider error', (provider) => {
    expect(validateDraft(draftWith({ 'llm.provider': provider }), STORED)).toStrictEqual({
      'llm.provider': catalogText('en', 'platform.defaults.error.provider'),
    });
  });

  const INVALID_NAMES: unknown[] = [
    'bad name',
    'a;rm -rf',
    '-x',
    '_x',
    'x'.repeat(201),
    'gpt-4o\n',
    'mod\u0000el',
    'a$(id)',
    'modèle',
    42,
    null,
  ];

  it.each(MODEL_PATHS.flatMap((path) => INVALID_NAMES.map((name): [string, unknown] => [path, name])))(
    '%s changed to %j is the model-name error',
    (path, name) => {
      expect(validateDraft(draftWith({ [path]: name }), STORED)).toStrictEqual({
        [path]: catalogText('en', 'platform.defaults.error.modelName'),
      });
    },
  );

  it.each(['llm.infomaniak_model', 'llm.anthropic_model', 'llm.openai_model'])(
    '%s changed from a name to "" is the model-name error',
    (path) => {
      expect(validateDraft(draftWith({ [path]: '' }), STORED)).toStrictEqual({
        [path]: catalogText('en', 'platform.defaults.error.modelName'),
      });
    },
  );

  const VALID_NAMES = ['my-model:v2', 'Qwen/Qwen2.5-7B-Instruct', 'llama3.1:8b', 'a', 'x'.repeat(200)];

  it.each(MODEL_PATHS.flatMap((path) => VALID_NAMES.map((name): [string, string] => [path, name])))(
    '%s changed to the valid %j has no error',
    (path, name) => {
      expect(validateDraft(draftWith({ [path]: name }), STORED)).toStrictEqual({});
    },
  );

  it('an unchanged empty model (vllm_model "") is never an error', () => {
    expect([storedValue('llm.vllm_model'), validateDraft(draftWith({ 'llm.vllm_model': '' }), STORED)]).toStrictEqual([
      '',
      {},
    ]);
  });

  it('an unchanged model is never validated, even one the rule would refuse', () => {
    const stored = deepFreeze({ ...rawSettings(), llm: { ...rawSettings().llm, openai_model: 'legacy model' } });

    expect(validateDraft(draftWith({ 'llm.openai_model': 'legacy model' }), stored)).toStrictEqual({});
  });

  it.each([true, false])('image_input %s is valid', (value) => {
    expect(validateDraft(draftWith({ 'llm.image_input': value }), STORED)).toStrictEqual({});
  });

  it.each(wrap(['true', 'false', 1, 0, null, undefined, {}, []]))('image_input %j is the invalid error', (value) => {
    expect(validateDraft(draftWith({ 'llm.image_input': value }), STORED)).toStrictEqual({
      'llm.image_input': catalogText('en', 'platform.defaults.error.invalid'),
    });
  });

  it.each([
    [30, 20],
    [90, 0],
    [1, 0],
  ])('a trash minimum of %d above the maximum of %d is the trash-order error on the minimum', (min, max) => {
    expect(
      validateDraft(draftWith({ 'retention.trash_min_days': min, 'retention.trash_max_days': max }), STORED),
    ).toStrictEqual({ 'retention.trash_min_days': catalogText('en', 'platform.defaults.error.trashOrder') });
  });

  it.each([
    [20, 20],
    [0, 0],
    [90, 90],
    [0, 90],
  ])('a trash minimum of %d with a maximum of %d is valid', (min, max) => {
    expect(
      validateDraft(draftWith({ 'retention.trash_min_days': min, 'retention.trash_max_days': max }), STORED),
    ).toStrictEqual({});
  });

  it.each([
    [91, 20, { 'retention.trash_min_days': rangeError(0, 90) }],
    [30, -1, { 'retention.trash_max_days': rangeError(0, 90) }],
    [100, 95, { 'retention.trash_min_days': rangeError(0, 90), 'retention.trash_max_days': rangeError(0, 90) }],
  ] as Array<[number, number, Record<string, string>]>)(
    'trash %d / %d out of range: only the range error, never the trash-order error',
    (min, max, errors) => {
      expect(
        validateDraft(draftWith({ 'retention.trash_min_days': min, 'retention.trash_max_days': max }), STORED),
      ).toStrictEqual(errors);
    },
  );

  const MANY_BAD = {
    'llm.provider': 'mistral',
    'llm.max_retries': 6,
    'llm.image_input': 'yes',
    'llm.anthropic_model': 'bad name',
    'files.render_dpi': 71,
    'retention.trash_min_days': 50,
    'retention.trash_max_days': 40,
    'security.session_idle_timeout_minutes': 14,
  };

  it('reports every invalid field at once, keyed by its path', () => {
    expect(validateDraft(draftWith(MANY_BAD), STORED)).toStrictEqual({
      'llm.provider': catalogText('en', 'platform.defaults.error.provider'),
      'llm.max_retries': rangeError(0, 5),
      'llm.image_input': catalogText('en', 'platform.defaults.error.invalid'),
      'llm.anthropic_model': catalogText('en', 'platform.defaults.error.modelName'),
      'files.render_dpi': rangeError(72, 300),
      'retention.trash_min_days': catalogText('en', 'platform.defaults.error.trashOrder'),
      'security.session_idle_timeout_minutes': rangeError(15, 480),
    });
  });

  it.each(['de', 'fr'] as const)('translates the messages into the active locale (%s)', (locale) => {
    setLocale(locale);

    expect(validateDraft(draftWith(MANY_BAD), STORED)).toStrictEqual({
      'llm.provider': catalogText(locale, 'platform.defaults.error.provider'),
      'llm.max_retries': rangeError(0, 5, locale),
      'llm.image_input': catalogText(locale, 'platform.defaults.error.invalid'),
      'llm.anthropic_model': catalogText(locale, 'platform.defaults.error.modelName'),
      'files.render_dpi': rangeError(72, 300, locale),
      'retention.trash_min_days': catalogText(locale, 'platform.defaults.error.trashOrder'),
      'security.session_idle_timeout_minutes': rangeError(15, 480, locale),
    });
  });

  it('never writes into the draft or the stored settings', () => {
    const draft = deepFreeze(draftWith(MANY_BAD));

    expect(Object.keys(validateDraft(draft, STORED)).length).toBe(7);
  });
});

// --- Patch ----------------------------------------------------------------------------------------

describe('buildDefaultsPatch', () => {
  it('null when nothing changed', () => {
    expect(buildDefaultsPatch(STORED, baseDraft())).toBeNull();
  });

  it('null after a change is reverted', () => {
    const draft = draftWith({ 'llm.max_retries': 4, 'files.render_dpi': 200 });
    draft.llm.max_retries = 2;
    draft.files.render_dpi = 150;

    expect(buildDefaultsPatch(STORED, draft)).toBeNull();
  });

  it.each(BOUNDS)('%s alone changed: only that field, in its section', (path, min, max) => {
    const value = storedValue(path) === min ? max : min;

    expect(buildDefaultsPatch(STORED, draftWith({ [path]: value }))).toStrictEqual(patchOf(path, value));
  });

  it.each([
    ['llm.provider', 'vllm'],
    ['llm.provider', 'anthropic'],
    ['llm.provider', 'openai'],
    ['llm.infomaniak_model', 'llama3'],
    ['llm.vllm_model', 'Qwen/Qwen2.5-0.5B-Instruct'],
    ['llm.anthropic_model', 'claude-opus-4-1'],
    ['llm.openai_model', 'gpt-4.1'],
    ['llm.image_input', false],
  ] as Array<[string, unknown]>)('%s changed to %j: only that field (never confirm_residency_orgs)', (path, value) => {
    expect(buildDefaultsPatch(STORED, draftWith({ [path]: value }))).toStrictEqual(patchOf(path, value));
  });

  it('a provider change plus a model change of another provider: both are sent', () => {
    expect(
      buildDefaultsPatch(STORED, draftWith({ 'llm.provider': 'anthropic', 'llm.infomaniak_model': 'llama3' })),
    ).toStrictEqual({ llm: { provider: 'anthropic', infomaniak_model: 'llama3' } });
  });

  it('groups the changed fields by section and omits the unchanged sections', () => {
    const draft = deepFreeze(
      draftWith({
        'llm.max_retries': 0,
        'llm.image_input': false,
        'files.render_dpi': 300,
        'security.lockout_minutes': 30,
        'security.session_max_lifetime_hours': 72,
      }),
    );

    expect(buildDefaultsPatch(STORED, draft)).toStrictEqual({
      llm: { max_retries: 0, image_input: false },
      files: { render_dpi: 300 },
      security: { lockout_minutes: 30, session_max_lifetime_hours: 72 },
    });
  });

  it('every section changed at once', () => {
    expect(
      buildDefaultsPatch(
        STORED,
        draftWith({
          'llm.max_input_tokens': 128000,
          'limits.max_message_length': 20000,
          'files.max_files_per_message': 3,
          'retention.trash_min_days': 7,
          'security.rate_limit_per_minute': 60,
        }),
      ),
    ).toStrictEqual({
      llm: { max_input_tokens: 128000 },
      limits: { max_message_length: 20000 },
      files: { max_files_per_message: 3 },
      retention: { trash_min_days: 7 },
      security: { rate_limit_per_minute: 60 },
    });
  });

  /** A draft that also carries read-only response fields and a confirmation count, as a careless copy would. */
  function draftWithReadOnlyExtras(values: Record<string, unknown>): DefaultsDraft {
    const draft = draftWith(values);
    Object.assign(draft.llm, {
      residency_orgs: 99,
      anthropic_key_configured: true,
      openai_key_configured: false,
      infomaniak_token_configured: false,
      infomaniak_available_models: ['injected'],
      vllm_available_models: ['injected'],
    });
    Object.assign(draft, { confirm_residency_orgs: 99 });
    return draft;
  }

  it('never sends a read-only field or confirm_residency_orgs, even when the draft carries them', () => {
    expect([
      buildDefaultsPatch(STORED, draftWithReadOnlyExtras({})),
      buildDefaultsPatch(STORED, draftWithReadOnlyExtras({ 'llm.provider': 'openai' })),
    ]).toStrictEqual([null, { llm: { provider: 'openai' } }]);
  });
});

// --- No content in logs ----------------------------------------------------------------------------

describe('platform defaults services logging', () => {
  it('never writes to the console', () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    isLlmProvider('__proto__');
    isValidModelName('a;rm');
    modelOptions(STORED.llm, 'infomaniak');
    providerKeyConfigured(STORED.llm, 'anthropic');
    const draft = draftFrom(STORED);
    validateDraft(draftWith({ 'llm.provider': 'mistral', 'llm.max_retries': 9 }), STORED);
    buildDefaultsPatch(STORED, draft);
    buildDefaultsPatch(STORED, draftWith({ 'llm.provider': 'openai' }));

    expect(spies.map((spy) => spy.mock.calls.length)).toEqual([0, 0, 0, 0, 0]);
  });
});
