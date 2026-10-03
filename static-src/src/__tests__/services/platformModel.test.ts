/**
 * Platform model service tests (issue #242: V1 model policy; decision D1 —
 * switching the platform's provider to a non-Swiss one needs a confirmation
 * naming how many organizations have data residency on; the server enforces
 * it with a 409, #168 renders the dialog).
 *
 * `@/services/platformModel` is a pure module. Contract (GH-242 §6):
 * - `SWISS_PROVIDERS = ['infomaniak', 'vllm'] as const` (the same set as the
 *   backend's `llm_policy.SWISS_PROVIDERS`).
 * - `isSwissProvider(provider)`: true only for an exact member of
 *   SWISS_PROVIDERS; anthropic, openai, '', an unknown or differently cased
 *   name and prototype names are not Swiss.
 * - `needsResidencyConfirmation(current, next)`: true iff `next !== current`
 *   and `next` is not Swiss (mirrors the server's 409 rule, so the UI asks
 *   before the server would refuse).
 *
 * Security notes: anything not exactly a Swiss provider counts as non-Swiss
 * (fail closed), so the UI never skips the confirmation the server requires.
 * No component is mounted and nothing touches the network.
 */
import { describe, it, expect } from 'vitest';
import { SWISS_PROVIDERS, isSwissProvider, needsResidencyConfirmation } from '@/services/platformModel';

describe('SWISS_PROVIDERS', () => {
  it('is exactly infomaniak and vllm', () => {
    expect([...SWISS_PROVIDERS]).toEqual(['infomaniak', 'vllm']);
  });
});

describe('isSwissProvider', () => {
  it.each(['infomaniak', 'vllm'])('treats %s as Swiss', (provider) => {
    expect(isSwissProvider(provider)).toBe(true);
  });

  it.each([
    'anthropic',
    'openai',
    '',
    'unknown',
    'Infomaniak',
    'VLLM',
    ' vllm',
    'infomaniak ',
    'swiss',
    '__proto__',
    'toString',
    'constructor',
    'length',
  ])('does not treat %j as Swiss', (provider) => {
    expect(isSwissProvider(provider)).toBe(false);
  });
});

describe('needsResidencyConfirmation', () => {
  it.each([
    ['infomaniak', 'anthropic'],
    ['infomaniak', 'openai'],
    ['vllm', 'anthropic'],
    ['vllm', 'openai'],
    ['anthropic', 'openai'],
    ['openai', 'anthropic'],
    ['', 'anthropic'],
    ['infomaniak', 'Infomaniak'],
  ])('asks before switching from %j to the non-Swiss %j', (current, next) => {
    expect(needsResidencyConfirmation(current, next)).toBe(true);
  });

  it.each([
    ['anthropic', 'infomaniak'],
    ['openai', 'vllm'],
    ['infomaniak', 'vllm'],
    ['vllm', 'infomaniak'],
  ])('does not ask when switching from %j to the Swiss %j', (current, next) => {
    expect(needsResidencyConfirmation(current, next)).toBe(false);
  });

  it.each([['anthropic'], ['openai'], ['infomaniak'], ['vllm']])(
    'does not ask when the provider stays %j',
    (provider) => {
      expect(needsResidencyConfirmation(provider, provider)).toBe(false);
    },
  );
});
