/**
 * Platform defaults pure services (issue #168: Platform console UI, Defaults
 * tab; backend settings from #160 and the model policy from #242).
 *
 * Framework-free logic `stores/platformDefaults.ts` uses: the provider and
 * model vocabulary, the bounds that mirror the backend, the editable draft
 * (a deep copy of exactly the editable fields), its validation and the diff
 * that becomes the PATCH body. The residency rule itself lives in
 * `services/platformModel.ts`.
 *
 * Security notes: nothing here logs; read-only fields (`residency_orgs`,
 * `*_configured`, `*_available_models`) never enter the draft or the patch, so
 * they can't be sent back; messages come from the i18n catalogs.
 */
import { t } from '@/i18n';
import type {
  LlmProvider,
  PlatformFiles,
  PlatformLimits,
  PlatformLLMPatch,
  PlatformRetention,
  PlatformSecurity,
  PlatformSettings,
  PlatformSettingsLLM,
  PlatformSettingsPatch,
} from '@/api/types';

export const LLM_PROVIDERS: readonly LlmProvider[] = ['infomaniak', 'vllm', 'anthropic', 'openai'];

const PROVIDER_SET: ReadonlySet<string> = new Set(LLM_PROVIDERS);

/** Exact, case-sensitive provider check. */
export function isLlmProvider(value: unknown): value is LlmProvider {
  return typeof value === 'string' && PROVIDER_SET.has(value);
}

export type ModelField = 'infomaniak_model' | 'vllm_model' | 'anthropic_model' | 'openai_model';

export const MODEL_FIELD: Record<LlmProvider, ModelField> = {
  infomaniak: 'infomaniak_model',
  vllm: 'vllm_model',
  anthropic: 'anthropic_model',
  openai: 'openai_model',
};

/** The models offered for a provider (a copy); Anthropic and OpenAI take free text. */
export function modelOptions(llm: PlatformSettingsLLM, provider: LlmProvider): string[] {
  if (provider === 'infomaniak') return [...llm.infomaniak_available_models];
  if (provider === 'vllm') return [...llm.vllm_available_models];
  return [];
}

/** Whether the provider's key/token is configured; `null` for vLLM (no key). */
export function providerKeyConfigured(llm: PlatformSettingsLLM, provider: LlmProvider): boolean | null {
  switch (provider) {
    case 'infomaniak':
      return llm.infomaniak_token_configured;
    case 'anthropic':
      return llm.anthropic_key_configured;
    case 'openai':
      return llm.openai_key_configured;
    default:
      return null;
  }
}

export const MODEL_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}$/;

export function isValidModelName(value: unknown): boolean {
  return typeof value === 'string' && MODEL_NAME_RE.test(value);
}

/** Integer bounds per `'<section>.<field>'`, mirroring the backend. */
export const DEFAULTS_BOUNDS: { [path: string]: { min: number; max: number } } = {
  'llm.max_input_tokens': { min: 1000, max: 2000000 },
  'llm.max_retries': { min: 0, max: 5 },
  'limits.max_tool_calls_per_message': { min: 1, max: 100 },
  'limits.max_pending_confirmations': { min: 1, max: 50 },
  'limits.confirmation_timeout_s': { min: 10, max: 3600 },
  'limits.max_message_length': { min: 1, max: 100000 },
  'limits.max_context_messages': { min: 1, max: 200 },
  'files.max_file_size_mb': { min: 1, max: 500 },
  'files.max_files_per_message': { min: 1, max: 50 },
  'files.max_pages_per_file': { min: 1, max: 1000 },
  'files.render_dpi': { min: 72, max: 300 },
  'retention.trash_min_days': { min: 0, max: 90 },
  'retention.trash_max_days': { min: 0, max: 90 },
  'retention.audit_months': { min: 6, max: 84 },
  'retention.org_deletion_grace_days': { min: 7, max: 90 },
  'security.rate_limit_per_minute': { min: 1, max: 600 },
  'security.lockout_after_failures': { min: 3, max: 100 },
  'security.lockout_window_minutes': { min: 1, max: 1440 },
  'security.lockout_minutes': { min: 1, max: 1440 },
  'security.session_idle_timeout_minutes': { min: 15, max: 480 },
  'security.session_max_lifetime_hours': { min: 1, max: 72 },
};

export interface DefaultsDraft {
  llm: Required<PlatformLLMPatch>;
  limits: PlatformLimits;
  files: PlatformFiles;
  retention: PlatformRetention;
  security: PlatformSecurity;
}

/** A deep copy of exactly the editable fields. */
export function draftFrom(settings: PlatformSettings): DefaultsDraft {
  const { llm } = settings;
  return {
    llm: {
      provider: llm.provider,
      infomaniak_model: llm.infomaniak_model,
      vllm_model: llm.vllm_model,
      anthropic_model: llm.anthropic_model,
      openai_model: llm.openai_model,
      max_input_tokens: llm.max_input_tokens,
      image_input: llm.image_input,
      max_retries: llm.max_retries,
    },
    limits: { ...settings.limits },
    files: { ...settings.files },
    retention: { ...settings.retention },
    security: { ...settings.security },
  };
}

/**
 * A copy of `draft` with `patch` applied on top (a null patch yields an equal
 * copy). Used to rebase the admin's own edits onto freshly loaded settings.
 */
export function applyPatch(draft: DefaultsDraft, patch: PlatformSettingsPatch | null): DefaultsDraft {
  const next: DefaultsDraft = {
    llm: { ...draft.llm },
    limits: { ...draft.limits },
    files: { ...draft.files },
    retention: { ...draft.retention },
    security: { ...draft.security },
  };
  if (patch === null) return next;
  for (const section of SECTIONS) {
    const changes = patch[section];
    if (changes !== undefined) Object.assign(next[section], changes);
  }
  return next;
}

const SECTIONS = ['llm', 'limits', 'files', 'retention', 'security'] as const;

/** The editable fields per section: the bounded numbers plus the llm provider, models and image flag. */
const EDITABLE_FIELDS: Record<(typeof SECTIONS)[number], string[]> = {
  llm: ['provider', ...Object.values(MODEL_FIELD), 'image_input'],
  limits: [],
  files: [],
  retention: [],
  security: [],
};
for (const path of Object.keys(DEFAULTS_BOUNDS)) {
  const [section, field] = path.split('.') as [(typeof SECTIONS)[number], string];
  EDITABLE_FIELDS[section].push(field);
}

/** Reads one field of a section by name (the draft and stored settings share the field names). */
function fieldOf(section: object, field: string): unknown {
  return (section as Record<string, unknown>)[field];
}

/** Field errors keyed `'<section>.<field>'`; empty when the draft is valid. */
export function validateDraft(draft: DefaultsDraft, stored: PlatformSettings): Record<string, string> {
  const errors: Record<string, string> = {};

  for (const [path, { min, max }] of Object.entries(DEFAULTS_BOUNDS)) {
    const [section, field] = path.split('.') as [(typeof SECTIONS)[number], string];
    const value = fieldOf(draft[section], field);
    if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
      errors[path] = t('platform.defaults.error.range', { min, max });
    }
  }

  if (!isLlmProvider(draft.llm.provider)) {
    errors['llm.provider'] = t('platform.defaults.error.provider');
  }

  for (const field of Object.values(MODEL_FIELD)) {
    if (draft.llm[field] !== stored.llm[field] && !isValidModelName(draft.llm[field])) {
      errors[`llm.${field}`] = t('platform.defaults.error.modelName');
    }
  }

  if (typeof draft.llm.image_input !== 'boolean') {
    errors['llm.image_input'] = t('platform.defaults.error.invalid');
  }

  if (
    errors['retention.trash_min_days'] === undefined &&
    errors['retention.trash_max_days'] === undefined &&
    draft.retention.trash_min_days > draft.retention.trash_max_days
  ) {
    errors['retention.trash_min_days'] = t('platform.defaults.error.trashOrder');
  }

  return errors;
}

/** Only the changed editable fields, grouped by section; `null` when nothing changed. */
export function buildDefaultsPatch(stored: PlatformSettings, draft: DefaultsDraft): PlatformSettingsPatch | null {
  const patch: Record<string, Record<string, unknown>> = {};

  for (const section of SECTIONS) {
    const changed: Record<string, unknown> = {};
    for (const field of EDITABLE_FIELDS[section]) {
      const next = fieldOf(draft[section], field);
      if (next !== fieldOf(stored[section], field)) changed[field] = next;
    }
    if (Object.keys(changed).length > 0) patch[section] = changed;
  }

  return Object.keys(patch).length > 0 ? (patch as PlatformSettingsPatch) : null;
}
