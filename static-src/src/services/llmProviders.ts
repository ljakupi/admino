/**
 * LLM provider display/logic helpers for the Settings → Agent page (issue #142;
 * issue #144: the trust note follows the active locale).
 *
 * Framework-free so it stays unit-testable: model dropdown options, the
 * user-facing provider label, and the trust note shown for the active
 * provider. Never mutates its inputs. Provider labels are brand names and
 * stay untranslated; the trust note comes from the i18n catalogs.
 */
import { t } from '@/i18n';
import type { LLMProviderName } from '@/api/types';

/**
 * The model dropdown options for a provider: the served/listed models plus
 * the currently configured model.
 *
 * The configured model is prepended when it is non-empty and not already in
 * `available`, so it stays visible even when the server is unreachable and
 * `available` is empty (e.g. right after a config change, before the next
 * model list refresh). Never duplicates an entry and never reorders
 * `available`. Does not mutate `available`.
 */
export function modelOptions(available: string[], configured: string): string[] {
  if (configured && !available.includes(configured)) {
    return [configured, ...available];
  }
  return [...available];
}

const PROVIDER_LABELS: Record<LLMProviderName, string> = {
  infomaniak: 'Infomaniak',
  anthropic: 'Claude',
  openai: 'OpenAI',
  vllm: 'vLLM',
};

/** The user-facing label for an API provider name. */
export function providerLabel(provider: LLMProviderName): string {
  return PROVIDER_LABELS[provider];
}

/**
 * Short trust/privacy copy for the active provider.
 *
 * Names the admino server (where settings, audit log and memory live) and
 * the active provider's label (the only party that sees the conversation
 * content). Must never claim that data "stays on this machine" — vLLM is
 * the only local option, and even it runs as a separate opt-in process.
 */
export function trustNote(provider: LLMProviderName): string {
  return t('settings.agent.trustNote', { provider: providerLabel(provider) });
}
