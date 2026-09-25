/**
 * LLM provider service tests (issue #142: Infomaniak provider).
 *
 * `@/services/llmProviders` holds the provider logic the Settings → Agent page
 * used to compute inline: the model dropdown options (served/listed models plus
 * the configured one), the user-facing provider labels, and the trust note that
 * replaces the no-longer-true "stay on this machine" copy. These tests assert
 * on the returned values only, never on how a component shows them.
 */
import { describe, it, expect } from 'vitest';
import { modelOptions, providerLabel, trustNote } from '@/services/llmProviders';
import type { LLMProviderName } from '@/api/types';

const QWEN_397B = 'Qwen/Qwen3.5-397B-A17B-FP8';
const QWEN_122B = 'Qwen/Qwen3.5-122B-A10B-FP8';
const MISTRAL = 'mistralai/Mistral-Small-3.2-24B';

const LABELS: ReadonlyArray<[LLMProviderName, string]> = [
  ['infomaniak', 'Infomaniak'],
  ['anthropic', 'Claude'],
  ['openai', 'OpenAI'],
  ['vllm', 'vLLM'],
];

const PROVIDERS: readonly LLMProviderName[] = LABELS.map(([provider]) => provider);

describe('llmProviders modelOptions', () => {
  it('prepends the configured model when the list does not contain it', () => {
    expect(modelOptions([QWEN_122B, MISTRAL], QWEN_397B)).toEqual([QWEN_397B, QWEN_122B, MISTRAL]);
  });

  it('does not duplicate the configured model when the list already contains it', () => {
    expect(modelOptions([QWEN_122B, QWEN_397B, MISTRAL], QWEN_397B)).toEqual([
      QWEN_122B,
      QWEN_397B,
      MISTRAL,
    ]);
  });

  it('ignores an empty configured model', () => {
    expect(modelOptions([QWEN_122B, MISTRAL], '')).toEqual([QWEN_122B, MISTRAL]);
  });

  it('returns only the configured model when nothing is listed', () => {
    expect(modelOptions([], QWEN_397B)).toEqual([QWEN_397B]);
  });

  it('returns no options when nothing is listed or configured', () => {
    expect(modelOptions([], '')).toEqual([]);
  });

  it('keeps the listed order instead of sorting', () => {
    expect(modelOptions([MISTRAL, QWEN_397B, QWEN_122B], QWEN_122B)).toEqual([
      MISTRAL,
      QWEN_397B,
      QWEN_122B,
    ]);
  });

  it('does not mutate the listed models when prepending', () => {
    const listed = [QWEN_122B, MISTRAL];

    modelOptions(listed, QWEN_397B);

    expect(listed).toEqual([QWEN_122B, MISTRAL]);
  });
});

describe('llmProviders providerLabel', () => {
  it.each(LABELS)('labels %s as %s', (provider, label) => {
    expect(providerLabel(provider)).toBe(label);
  });
});

describe('llmProviders trustNote', () => {
  it.each(LABELS)('names the active provider %s by its label %s', (provider, label) => {
    expect(trustNote(provider)).toContain(label);
  });

  it.each(PROVIDERS)('names the admino server for %s', (provider) => {
    const note = trustNote(provider);

    expect([/admino/i.test(note), /\bserver\b/i.test(note)]).toEqual([true, true]);
  });

  it.each(PROVIDERS)('does not claim data stays on this machine for %s', (provider) => {
    expect(trustNote(provider)).not.toMatch(/stays? on this machine/i);
  });
});
